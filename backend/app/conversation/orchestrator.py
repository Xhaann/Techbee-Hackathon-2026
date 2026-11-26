"""Conversation orchestration.

Responsibilities are kept apart:
- intents.classify decides what the user wants and whether any tool may run;
- this module runs the turn: context, dispatch, investigation lifecycle, events and cancellation;
- DiagnosisAgent and ToolExecutor (unchanged engines) perform diagnosis and every tool call;
- human-only actions are never performed here; they are surfaced for a person to approve in the workspace.
"""
import asyncio
import hashlib
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from starlette.concurrency import run_in_threadpool

from app.agent import DiagnosisAgent, build_report
from app.agent.tools import KNOWLEDGE_TOOL
from app.conversation.composer import ReplyComposer
from app.conversation.digests import digest
from app.conversation.entities import TopologyIndex, topology_index
from app.conversation.intents import TOPIC_LABEL, Planner, classify
from app.conversation.models import (
    Clarification,
    ConversationContext,
    EvidenceReference,
    ExecutionSummary,
    HumanConfirmation,
    Intent,
    IntentResult,
    IntentView,
    Investigation,
    Message,
    PendingAction,
    PendingClarification,
    PlannedCall,
    QuickAction,
    SuggestedAction,
    ToolStep,
    TurnResult,
)
from app.conversation.store import ConversationState, ConversationStore, TurnHandle, new_id, now
from app.core.exceptions import AppError
from app.engine.evidence import build_catalog
from app.engine.executor import MAX_TOOL_CALLS, ToolCallRecord, ToolExecutor
from app.engine.planner import DiagnosisRequestError
from app.engine.registry import REGISTRY
from app.engine.schema import Diagnosis, EvidenceItem, EvidenceType
from app.incidents.models import Incident
from app.knowledge.retrieval import KnowledgeQuery, render
from app.network.models import PathService
from app.network.repository import list_scenario_ids
from app.security.permissions import HUMAN_ONLY, Permission, Principal
from app.security.secrets import redact

logger = logging.getLogger(__name__)

MAX_NOTES = 6
MAX_FACT_EVIDENCE = 12
FAULT_LABEL = {"wan_isp": "WAN / ISP circuit", "routing": "routing", "switching": "switching", "firewall": "firewall policy",
               "vlan_authentication": "VLAN / 802.1X authentication", "dhcp": "DHCP", "dns": "DNS",
               "network_device_failure": "network device failure", "interface_link": "interface / physical link",
               "shared_infrastructure": "shared infrastructure", "unknown": "unknown"}
TOOL_LABEL = {"get_topology": "Site topology", "get_device_logs": "Device logs", "get_interface_stats": "Interface statistics",
              "get_routing_state": "Routing state", "get_firewall_logs": "Firewall logs", "get_dhcp_dns_status": "DHCP and DNS status",
              "check_network_reachability": "Path reachability", "analyze_packet_loss": "Packet loss analysis",
              "analyze_interface_errors": "Interface error analysis", "analyze_routing_adjacency": "Routing adjacency analysis",
              "check_device_availability": "Device availability", "analyze_network_dependencies": "Dependency analysis",
              KNOWLEDGE_TOOL: "Knowledge search"}
EVIDENCE_KIND = {
    EvidenceType.OBSERVED_FINDING: ("an observed finding", "It was measured directly in the synthetic telemetry, not inferred."),
    EvidenceType.INFERRED_FINDING: ("an inferred finding", "The tool inferred it from other data, so it is weaker than a direct observation."),
    EvidenceType.OBSERVED_RESULT: ("an observed result", "It is the outcome of an evaluation the tool ran, such as a path or availability check."),
    EvidenceType.RECORD: ("a log record", "It is a raw log line, quoted as recorded."),
}
SCOPE_TEXT = {"everyone": "everyone at the site", "some": "some users", "single": "a single user"}
SCOPE_REPORT = {"everyone": "All users at the affected site are impacted.", "some": "Only some users are impacted.",
                "single": "A single user is impacted."}
CAPABILITIES = [
    "Talk through the incident and explain the diagnosis and its evidence (E1, E2, ...) without re-running anything",
    "Run targeted read-only checks when asked: routing, BGP/OSPF adjacencies, interfaces, packet loss, interface errors, logs, "
    "reachability, firewall logs, DHCP/DNS, topology and dependencies",
    f"Run a full diagnosis when asked: at most {MAX_TOOL_CALLS} read-only tool calls, correlated into a hypothesis with confidence and evidence",
    "Search the troubleshooting playbooks and site runbooks (guidance, not evidence)",
    "Never change devices or incidents: confirming, escalating, saving, closing and remediation are human actions",
]
HUMAN_ACTIONS: dict[str, tuple[str, Permission, str]] = {
    "confirm": ("Confirm the fault domain", Permission.CONFIRM_CLASSIFICATION, "Review and confirm"),
    "escalate": ("Escalate the incident", Permission.UPDATE_INCIDENTS, "Escalate"),
    "close": ("Close the incident", Permission.CLOSE_REOPEN_INCIDENTS, "Close incident"),
    "reopen": ("Reopen the incident", Permission.CLOSE_REOPEN_INCIDENTS, "Reopen"),
    "severity": ("Change the severity", Permission.CHANGE_SEVERITY_PRIORITY, "Change severity"),
    "priority": ("Change the priority", Permission.CHANGE_SEVERITY_PRIORITY, "Change priority"),
    "propose": ("Propose a resolution", Permission.PROPOSE_RESOLUTIONS, "Propose resolution"),
    "verify": ("Verify the resolution", Permission.VERIFY_RESOLUTIONS, "Verify resolution"),
    "assign": ("Assign the incident", Permission.UPDATE_INCIDENTS, "Edit details"),
}
SAVEABLE = {"acknowledged", "investigating", "diagnosed", "escalated", "monitoring"}
StepStatus = Literal["executed", "failed", "rejected", "duplicate", "cancelled"]


def can(principal: Principal, permission: Permission) -> bool:
    return permission in principal.permissions and (permission not in HUMAN_ONLY or principal.kind.value == "human")


def act(kind: str, label: str, params: dict[str, Any] | None = None, *, tools: bool = False, human: bool = False,
        allowed: bool = True, reason: str | None = None) -> SuggestedAction:
    return SuggestedAction(action_id=new_id("ACT", 4), kind=kind, label=label, params=params or {}, executes_tools=tools,
                           requires_human=human, allowed=allowed, reason=reason)


def reply(label: str) -> SuggestedAction:
    return act("reply", label, {"text": label})


def reference(item: EvidenceItem, investigation_id: str | None = None, diagnosis_id: str | None = None) -> EvidenceReference:
    return EvidenceReference(evidence_id=item.evidence_id, source="investigation" if investigation_id else "incident_diagnosis",
                             investigation_id=investigation_id, diagnosis_id=diagnosis_id, tool=item.tool, call_id=item.call_id,
                             evidence_type=item.evidence_type.value, code=item.code, device_id=item.device_id, summary=item.summary,
                             timestamp=item.timestamp)


def evidence_fact(item: EvidenceItem, role: str | None = None) -> dict[str, Any]:
    fact = {"evidence_id": item.evidence_id, "type": item.evidence_type.value, "code": item.code, "device_id": item.device_id,
            "tool": item.tool, "call_id": item.call_id, "summary": item.summary,
            "timestamp": item.timestamp.isoformat() if item.timestamp else None,
            "references": [f"{ref.collection}:{ref.record_id}" for ref in item.references[:5]]}
    if role:
        fact["role"] = role
    return fact


def bullet(item: EvidenceItem) -> str:
    return f"- **{item.evidence_id}**: {item.summary}"


def step_status(record: ToolCallRecord) -> StepStatus:
    if record.status == "executed":
        return "executed" if record.succeeded else "failed"
    if record.error_code == "CANCELLED":
        return "cancelled"
    return record.status if record.status in ("failed", "rejected", "duplicate") else "rejected"


@dataclass
class Outcome:
    template: str
    facts: dict[str, Any]
    clarification: Clarification | None = None
    actions: list[SuggestedAction] = field(default_factory=list)
    confirmations: list[HumanConfirmation] = field(default_factory=list)
    evidence: list[EvidenceReference] = field(default_factory=list)
    investigation: Investigation | None = None
    status: Literal["completed", "cancelled", "failed"] = "completed"
    knowledge_searches: int = 0
    use_model: bool = True
    footer: str | None = None


@dataclass
class Turn:
    state: ConversationState
    principal: Principal
    handle: TurnHandle
    user: Message
    action: QuickAction | None
    started: float = field(default_factory=time.monotonic)
    incident: Incident | None = None
    intent: IntentResult | None = None
    observer: "ProgressObserver | None" = None


class ProgressObserver:
    """Bridges ToolExecutor progress (any thread) to conversation events (event loop thread)."""

    def __init__(self, service: "ConversationService", turn: Turn, investigation: Investigation,
                 loop: asyncio.AbstractEventLoop) -> None:
        self.service = service
        self.turn = turn
        self.investigation = investigation
        self.loop = loop
        self.records: list[ToolCallRecord] = []
        self.lock = threading.Lock()
        self.knowledge_searches = 0
        self.closed = False

    def started(self, call_id: str, tool: str, arguments: dict[str, Any]) -> None:
        self.loop.call_soon_threadsafe(self.on_started, call_id, tool, dict(arguments))

    def finished(self, record: ToolCallRecord) -> None:
        with self.lock:
            self.records.append(record)
            catalog = build_catalog(list(self.records))
        evidence = [item for item in catalog if item.call_id == record.call_id]
        self.loop.call_soon_threadsafe(self.on_finished, record, evidence, digest(record))

    def knowledge(self, query: str, document_ids: list[str], status: str) -> None:
        self.loop.call_soon_threadsafe(self.on_knowledge, query, list(document_ids), status)

    def emit(self, event: str, data: dict[str, Any]) -> None:
        self.service.emit(self.turn, event, data | {"investigation_id": self.investigation.investigation_id})

    def on_started(self, call_id: str, tool: str, arguments: dict[str, Any]) -> None:
        if self.closed:
            return
        index = len(self.investigation.steps)
        self.investigation.steps.append(ToolStep(call_id=call_id, tool=tool, arguments=arguments, status="running", started_at=now()))
        self.emit("tool.started", {"call_id": call_id, "tool": tool, "label": TOOL_LABEL.get(tool, tool), "arguments": arguments,
                                   "index": index + 1, "budget_limit": self.investigation.budget_limit})

    def on_finished(self, record: ToolCallRecord, evidence: list[EvidenceItem], summary: str) -> None:
        if self.closed:
            return
        status = step_status(record)
        step = ToolStep(call_id=record.call_id, tool=record.tool, arguments=record.arguments, status=status,
                        error_code=record.error_code, evidence_ids=[item.evidence_id for item in evidence], summary=summary,
                        finished_at=now())
        steps = self.investigation.steps
        position = next((i for i, s in enumerate(steps) if s.call_id == record.call_id and s.status == "running"), None)
        if position is None:
            steps.append(step)
        else:
            steps[position] = step.model_copy(update={"started_at": steps[position].started_at})
        self.emit({"executed": "tool.completed", "failed": "tool.failed"}.get(status, "tool.skipped"), {
            "call_id": record.call_id, "tool": record.tool, "label": TOOL_LABEL.get(record.tool, record.tool), "status": status,
            "error_code": record.error_code, "summary": summary,
            "evidence": [{"evidence_id": item.evidence_id, "code": item.code, "type": item.evidence_type.value,
                          "device_id": item.device_id, "summary": item.summary} for item in evidence[:8]],
        })
        self.progress()

    def on_knowledge(self, query: str, document_ids: list[str], status: str) -> None:
        if self.closed:
            return
        self.knowledge_searches += 1
        self.investigation.knowledge_documents = list(dict.fromkeys(self.investigation.knowledge_documents + document_ids))
        self.investigation.steps.append(ToolStep(call_id=None, tool=KNOWLEDGE_TOOL, arguments={"query": query[:200]},
                                                 status="executed" if status == "guidance_only" else "rejected",
                                                 summary=f"{len(document_ids)} guidance documents (unverified)", finished_at=now()))
        self.emit("knowledge.searched", {"query": query[:200], "document_ids": document_ids, "status": status})
        self.progress()

    def progress(self) -> None:
        steps = self.investigation.steps
        self.emit("investigation.progress", {
            "tool_calls": len([s for s in steps if s.tool != KNOWLEDGE_TOOL and s.status in ("executed", "failed")]),
            "attempts": len([s for s in steps if s.status != "running"]), "budget_limit": self.investigation.budget_limit,
            "running": any(s.status == "running" for s in steps),
        })


class ConversationService:
    def __init__(self, services: Any, store: ConversationStore | None = None, index: TopologyIndex | None = None) -> None:
        self.services = services
        self.store = store or ConversationStore()
        self.index = index or topology_index()
        self.composer = ReplyComposer(services.agent, set(self.index.devices))

    @property
    def model_available(self) -> bool:
        return self.services.agent.model is not None

    # ---------- conversations ----------

    async def create(self, principal: Principal, incident_id: str | None, scenario_id: str | None,
                     mode: Literal["auto", "rule_based"]) -> ConversationState:
        context = ConversationContext()
        title = "New conversation"
        if incident_id:
            incident = await run_in_threadpool(self.services.secured_incidents.get_incident, principal, incident_id)
            if scenario_id and incident.dataset_scenario_id and scenario_id != incident.dataset_scenario_id:
                raise AppError(f"scenario_id does not match the incident's dataset scenario '{incident.dataset_scenario_id}'",
                               code="VALIDATION_ERROR", status_code=422)
            context = ConversationContext(incident_id=incident.incident_id, scenario_id=incident.dataset_scenario_id or scenario_id,
                                          site_ids=list(incident.site_ids[:5]))
            title = f"{incident.incident_id}: {incident.title}"
        elif scenario_id:
            context = ConversationContext(scenario_id=scenario_id)
            title = f"Scenario {scenario_id}"
        if context.scenario_id and context.scenario_id not in list_scenario_ids():
            raise AppError(f"Unknown scenario '{context.scenario_id}'", code="NOT_FOUND", status_code=404)
        return self.store.create(principal.subject, context, mode, title)

    def reset_context(self, state: ConversationState) -> ConversationContext:
        if state.active is not None:
            raise AppError("Wait for the current turn to finish or cancel it first", code="TURN_IN_PROGRESS", status_code=409)
        old = state.context
        state.context = ConversationContext(incident_id=old.incident_id, scenario_id=old.scenario_id,
                                            site_ids=old.site_ids if old.incident_id else [])
        self.emit_state(state, "context.reset", {"context": state.context.model_dump(mode="json")})
        return state.context

    def emit_state(self, state: ConversationState, event: str, data: dict[str, Any], turn_id: str | None = None) -> None:
        self.store.emit(state, event, turn_id, data)

    def emit(self, turn: Turn, event: str, data: dict[str, Any]) -> None:
        self.store.emit(turn.state, event, turn.handle.turn_id, data)

    # ---------- turn lifecycle ----------

    def start_turn(self, state: ConversationState, principal: Principal, content: str | None,
                   action: QuickAction | None) -> TurnHandle:
        if state.active is not None:
            raise AppError("The assistant is still working on the previous message. Wait for it or cancel it first.",
                           code="TURN_IN_PROGRESS", status_code=409)
        handle = TurnHandle(turn_id=new_id("TRN", 6), started_at=now())
        text = redact(" ".join((content or "").split()))[:4000] or (action.label if action and action.label else self.action_text(action))
        user = Message(message_id=new_id("MSG", 6), turn_id=handle.turn_id, role="user", content=text, created_at=now(), action=action)
        state.add_message(user)
        state.active = handle
        turn = Turn(state=state, principal=principal, handle=handle, user=user, action=action)
        self.emit(turn, "turn.started", {"message": user.model_dump(mode="json")})
        handle.task = asyncio.create_task(self.run_turn(turn))
        return handle

    @staticmethod
    def action_text(action: QuickAction | None) -> str:
        if action is None:
            return ""
        if action.kind == "full_diagnosis":
            return "Run a full diagnosis"
        if action.kind == "targeted_check":
            target = (action.arguments or {}).get("device_id") or (action.arguments or {}).get("site_id") or ""
            return f"Run {TOOL_LABEL.get(action.tool or '', action.tool or 'check').lower()} {target}".strip()
        if action.kind == "explain_evidence":
            return f"Explain {', '.join(action.evidence_ids) or 'the evidence'}"
        return "What's the status?"

    def cancel(self, state: ConversationState) -> TurnHandle | None:
        handle = state.active
        if handle is None or handle.cancel_requested:
            return handle
        handle.cancel_requested = True
        handle.cancel_event.set()
        self.store.emit(state, "turn.cancelling", handle.turn_id, {"investigation_id": handle.investigation_id})
        if handle.task is not None:
            handle.task.cancel()
        return handle

    async def run_turn(self, turn: Turn) -> TurnResult:
        state = turn.state
        try:
            outcome = await self.process(turn)
            result = await self.finish(turn, outcome)
            return result
        except asyncio.CancelledError:
            current = asyncio.current_task()
            if current is not None:
                current.uncancel()
            result = await self.finish(turn, self.cancelled(turn))
            return result
        except Exception:
            logger.exception("Conversation turn failed")
            try:
                return await self.finish(turn, self.failed(turn))
            except Exception:
                logger.exception("Conversation turn could not be finalised")
                self.emit(turn, "turn.failed", {"error": {"code": "TURN_FAILED", "message": "The assistant could not complete this turn"}})
                raise
        finally:
            state.active = None
            state.updated_at = now()

    async def process(self, turn: Turn) -> Outcome:
        try:
            turn.incident = await self.load_incident(turn)
        except AppError as exc:
            turn.intent = IntentResult(intent=Intent.GENERAL, confidence="low", source="rules")
            return Outcome(template=f"I can't read {turn.state.context.incident_id} right now: {exc.message}. Nothing was run.",
                           facts=self.error_facts(), status="failed", use_model=False)
        turn.intent = self.understand(turn)
        intent = turn.intent
        self.emit(turn, "intent.classified", {"intent": intent.intent.value, "confidence": intent.confidence, "source": intent.source,
                                              "topics": intent.topics, "entities": intent.entities.model_dump(mode="json"),
                                              "executes_tools": bool(intent.planned_calls) or intent.intent == Intent.FULL_DIAGNOSIS})
        self.merge_context(turn)
        handler = getattr(self, f"on_{intent.intent.value}")
        try:
            return await handler(turn)
        except AppError as exc:
            return Outcome(template=f"I couldn't do that: {exc.message}. Nothing was changed.", facts=self.error_facts(),
                           status="failed", use_model=False)

    async def load_incident(self, turn: Turn) -> Incident | None:
        incident_id = turn.state.context.incident_id
        if not incident_id:
            return None
        return await run_in_threadpool(self.services.secured_incidents.get_incident, turn.principal, incident_id)

    def understand(self, turn: Turn) -> IntentResult:
        action = turn.action
        context = turn.state.context
        if action is None:
            return classify(turn.user.content, context, self.index)
        if action.kind == "full_diagnosis":
            return IntentResult(intent=Intent.FULL_DIAGNOSIS, confidence="high", source="quick_action", rerun=True)
        if action.kind == "explain_evidence":
            result = IntentResult(intent=Intent.EVIDENCE_EXPLANATION, confidence="high", source="quick_action")
            result.entities.evidence_ids = list(action.evidence_ids)
            return result
        if action.kind == "status":
            return IntentResult(intent=Intent.STATUS, confidence="high", source="quick_action")
        call = PlannedCall(tool=action.tool or "", arguments=dict(action.arguments or {}), reason="Requested with a quick action")
        return IntentResult(intent=Intent.TARGETED_DIAGNOSTIC, confidence="high", source="quick_action", planned_calls=[call], rerun=True)

    def merge_context(self, turn: Turn) -> None:
        context = turn.state.context
        intent = turn.intent
        entities = intent.entities
        describes = intent.intent in (Intent.SYMPTOM_REPORT, Intent.CLARIFICATION, Intent.FULL_DIAGNOSIS)
        if describes:
            context.site_ids = list(dict.fromkeys(context.site_ids + entities.site_ids))[:5]
            context.device_ids = list(dict.fromkeys(context.device_ids + entities.device_ids))[:10]
            context.services = list(dict.fromkeys(context.services + entities.services))[:5]
            context.symptoms = list(dict.fromkeys(context.symptoms + entities.symptoms))[:10]
            context.scope = entities.scope or context.scope
            context.timeframe = entities.timeframe or context.timeframe
            informative = bool(entities.scope or entities.symptoms or entities.services or entities.site_ids or entities.device_ids
                               or entities.timeframe)
            if turn.action is None and len(turn.user.content.split()) > 1 and (intent.intent != Intent.FULL_DIAGNOSIS or informative):
                context.notes = (context.notes + [turn.user.content[:500]])[-MAX_NOTES:]
        if entities.device_ids and intent.intent in (Intent.TARGETED_DIAGNOSTIC, Intent.SYMPTOM_REPORT):
            context.focus_device_id = entities.device_ids[0]
        if intent.intent not in (Intent.CONFIRMATION, Intent.DECLINE, Intent.GREETING, Intent.GENERAL, Intent.STATUS,
                                 Intent.EVIDENCE_EXPLANATION, Intent.CAPABILITIES, Intent.KNOWLEDGE, Intent.INCIDENT_QUERY,
                                 Intent.CANCELLATION):
            context.pending_action = None
        if intent.intent in (Intent.FULL_DIAGNOSIS, Intent.TARGETED_DIAGNOSTIC, Intent.HUMAN_ACTION, Intent.CONFIRMATION,
                             Intent.DECLINE):
            context.pending_clarification = None

    async def finish(self, turn: Turn, outcome: Outcome) -> TurnResult:
        state = turn.state
        intent = turn.intent or IntentResult(intent=Intent.GENERAL, confidence="low", source="rules")
        message_id = new_id("MSG", 6)
        streamed: list[str] = []

        def on_delta(text: str) -> None:
            streamed.append(text)
            self.emit(turn, "assistant.delta", {"message_id": message_id, "text": text})

        self.emit(turn, "assistant.typing", {"state": "start", "message_id": message_id})
        history = [(m.role, m.content) for m in state.messages[:-1] if m.status == "completed"]
        issues: list[str] = []
        if outcome.use_model and outcome.status != "cancelled" and self.composer.available:
            try:
                text, composer, issues = await self.composer.compose(history, turn.user.content, outcome.facts, outcome.template,
                                                                     on_delta)
            except asyncio.CancelledError:
                current = asyncio.current_task()
                if current is not None:
                    current.uncancel()
                text, composer = outcome.template, "template"
        else:
            text, composer = outcome.template, "template"
        if composer == "model" and outcome.footer:
            # Safety statements are not left to the model: they are appended verbatim.
            text = f"{text}\n\n{outcome.footer}"
        self.emit(turn, "assistant.typing", {"state": "stop", "message_id": message_id})
        investigation = outcome.investigation
        message = Message(message_id=message_id, turn_id=turn.handle.turn_id, role="assistant", content=text, created_at=now(),
                          intent=intent.intent, status=outcome.status, composer=composer,
                          investigation_id=investigation.investigation_id if investigation else None,
                          evidence_refs=outcome.evidence[:20], suggested_actions=outcome.actions[:6], clarification=outcome.clarification,
                          human_confirmations=outcome.confirmations)
        state.add_message(message)
        self.emit(turn, "assistant.message", {"message": message.model_dump(mode="json"), "replaced": bool(streamed) and composer != "model",
                                              "composer_issues": issues})
        steps = investigation.steps if investigation else []
        mode = investigation.mode if investigation else "none"
        execution = ExecutionSummary(
            status=outcome.status, duration_ms=int((time.monotonic() - turn.started) * 1000),
            tool_calls=len([s for s in steps if s.status in ("executed", "failed")]),
            diagnostic_tool_calls=len([s for s in steps if s.tool in REGISTRY and s.status in ("executed", "failed")]),
            knowledge_searches=outcome.knowledge_searches + len([s for s in steps if s.tool == KNOWLEDGE_TOOL]),
            budget_used=investigation.budget_used if investigation else 0,
            budget_limit=investigation.budget_limit if investigation else MAX_TOOL_CALLS, tools=steps, mode=mode,
            model=investigation.model if investigation else None, composer=composer,
            fallback_used=investigation.fallback_used if investigation else False,
        )
        result = TurnResult(
            conversation_id=state.conversation_id, turn_id=turn.handle.turn_id,
            intent=IntentView(name=intent.intent, confidence=intent.confidence, source=intent.source, entities=intent.entities,
                              topics=intent.topics),
            response=text, user_message=turn.user, assistant_message=message, clarification=outcome.clarification,
            investigation_id=investigation.investigation_id if investigation else None, execution=execution,
            evidence_references=message.evidence_refs, suggested_actions=message.suggested_actions,
            human_confirmations=message.human_confirmations, context=state.context.model_copy(deep=True),
        )
        self.emit(turn, "turn.completed", {"status": outcome.status, "result": result.model_dump(mode="json")})
        return result

    @staticmethod
    def error_facts(kind: str = "error") -> dict[str, Any]:
        return {"kind": kind, "tools_ran_this_turn": False, "evidence_ids": []}

    def failed(self, turn: Turn) -> Outcome:
        investigation = turn.observer.investigation if turn.observer else None
        if investigation is not None and investigation.status == "running" and turn.observer is not None:
            turn.observer.closed = True
            investigation.steps = [s.model_copy(update={"status": "cancelled"}) if s.status == "running" else s
                                   for s in investigation.steps]
            investigation.evidence = build_catalog(list(turn.observer.records))
            investigation.error = "The investigation stopped because of an internal error"
            self.close_investigation(turn, investigation, "failed")
        return Outcome(template="Something went wrong on my side while handling that, so I stopped. Nothing was changed. "
                                "You can try again.", facts=self.error_facts(), investigation=investigation,
                       status="failed", use_model=False)

    def cancelled(self, turn: Turn) -> Outcome:
        observer = turn.observer
        investigation = observer.investigation if observer else None
        if observer is not None:
            observer.closed = True
            investigation.steps = [s.model_copy(update={"status": "cancelled"}) if s.status == "running" else s
                                   for s in investigation.steps]
            records = list(observer.records)
            investigation.evidence = build_catalog(records)
            investigation.status = "cancelled"
            investigation.finished_at = now()
            investigation.duration_ms = int((investigation.finished_at - investigation.started_at).total_seconds() * 1000)
            investigation.budget_used = len([s for s in investigation.steps if s.status != "cancelled"])
            investigation.error = "Cancelled by the user"
            self.emit(turn, "investigation.cancelled", {"investigation_id": investigation.investigation_id,
                                                        "summary": investigation.summary().model_dump(mode="json")})
            done = len([s for s in investigation.steps if s.status in ("executed", "failed")])
            evidence = investigation.evidence
            template = (f"Stopped. I'd completed {done} of the read-only checks before you cancelled"
                        + (f", and kept the partial evidence ({evidence[0].evidence_id}-{evidence[-1].evidence_id}) for reference"
                           if evidence else "")
                        + ". I haven't drawn a conclusion from it, and nothing was changed.")
            refs = [reference(item, investigation.investigation_id) for item in evidence[:MAX_FACT_EVIDENCE]]
            return Outcome(template=template, facts=self.facts(turn, "cancelled"), evidence=refs, investigation=investigation,
                           status="cancelled", use_model=False, actions=[act("full_diagnosis", "Run the full diagnosis", tools=True)])
        return Outcome(template="Stopped. Nothing was run and nothing was changed.", facts=self.facts(turn, "cancelled"),
                       status="cancelled", use_model=False)

    # ---------- shared facts ----------

    def incident_brief(self, incident: Incident | None) -> dict[str, Any] | None:
        if incident is None:
            return None
        record = incident.active_diagnosis
        diagnosis = None
        if record is not None:
            d = record.diagnosis
            diagnosis = {
                "diagnosis_id": record.diagnosis_id, "fault_domain": d.fault.fault_domain.value, "root_cause": d.fault.root_cause,
                "confidence": d.confidence.level.value, "method": d.method.value, "evidence_count": len(d.evidence),
                "supporting_evidence_ids": d.fault.supporting_evidence_ids[:8], "human_verified": False,
                "next_checks": [{"device_id": c.device_id, "command": c.command, "purpose": c.purpose} for c in d.next_checks[:3]],
                "escalation": {"team": d.escalation.team, "priority": d.escalation.priority.value, "reason": d.escalation.reason},
                "unknowns": (d.escalation.unknowns + d.limitations)[:4],
            }
        return {
            "incident_id": incident.incident_id, "title": incident.title, "description": incident.description[:600],
            "status": incident.status.value, "severity": incident.severity.value, "priority": incident.priority.value,
            "site_ids": incident.site_ids, "symptoms": incident.symptoms[:6], "assigned_team": incident.assigned_team,
            "assigned_owner": incident.assigned_owner,
            "confirmed_fault_domain": incident.classification.confirmed_fault_domain.value
            if incident.classification.confirmed_fault_domain else None,
            "escalations": [{"escalation_id": e.escalation_id, "team": e.assigned_team or e.recommended_team, "status": e.status.value,
                             "priority": e.priority.value} for e in incident.escalations[-5:]],
            "active_diagnosis": diagnosis, "telemetry_scenario": incident.dataset_scenario_id,
        }

    def facts(self, turn: Turn, kind: str, **extra: Any) -> dict[str, Any]:
        context = turn.state.context
        facts: dict[str, Any] = {
            "kind": kind, "tools_ran_this_turn": False, "evidence_ids": [],
            "incident": self.incident_brief(turn.incident),
            "conversation_context": {"sites": context.site_ids, "services": context.services, "symptoms": context.symptoms,
                                     "scope": context.scope, "timeframe": context.timeframe, "focus_device": context.focus_device_id},
            "user_can": {"run_diagnostics": can(turn.principal, Permission.RUN_DIAGNOSTICS),
                         "confirm_classification": can(turn.principal, Permission.CONFIRM_CLASSIFICATION)},
        }
        facts.update(extra)
        brief = facts["incident"]
        if brief and brief.get("active_diagnosis"):
            facts["evidence_ids"] = sorted(set(facts["evidence_ids"]) | set(brief["active_diagnosis"]["supporting_evidence_ids"]))
        return facts

    def site_names(self, sites: list[str]) -> str:
        names = [self.index.site_names.get(site, site) for site in sites]
        return " and ".join(names) if names else "the affected site"

    def diagnosis_line(self, incident: Incident | None) -> str:
        record = incident.active_diagnosis if incident else None
        if record is None:
            return ""
        d = record.diagnosis
        return (f"The current diagnosis points to {FAULT_LABEL.get(d.fault.fault_domain.value, d.fault.fault_domain.value)} "
                f"({d.confidence.level.value.replace('_', ' ')} confidence): {d.fault.root_cause}")

    def can_diagnose(self, turn: Turn) -> bool:
        return can(turn.principal, Permission.RUN_DIAGNOSTICS) and bool(turn.state.context.scenario_id)

    def propose_diagnosis(self, turn: Turn) -> list[SuggestedAction]:
        if not self.can_diagnose(turn):
            return []
        turn.state.context.pending_action = PendingAction(kind="full_diagnosis", proposed_at=now())
        return [act("full_diagnosis", "Run full diagnosis", tools=True), reply("Not yet")]

    # ---------- intent handlers (no tools) ----------

    async def on_greeting(self, turn: Turn) -> Outcome:
        incident = turn.incident
        actions = []
        if incident is not None:
            line = self.diagnosis_line(incident)
            confirmed = incident.classification.confirmed_fault_domain
            state = (f"It's {incident.status.value}. " if incident.status.value in ("resolved", "closed") else "")
            review = (f"A person confirmed the fault domain as {FAULT_LABEL.get(confirmed.value, confirmed.value)}. " if confirmed
                      else "It's still a hypothesis until a person confirms it. ")
            template = (f"Hi! I'm keeping an eye on {incident.incident_id}: {incident.title}. {state}"
                        + (f"{line}. {review}" if line else "There's no diagnosis on it yet. ")
                        + "I can walk you through the evidence, run a specific read-only check, or start a full investigation "
                          "when you ask. What are you seeing?")
            if line:
                actions.append(reply("Explain the current diagnosis"))
        else:
            template = ("Hi! I'm the network operations assistant. Tell me what users are seeing, ask about a device or a site, "
                        "or ask me to diagnose a problem. I only run read-only checks, and only when you ask.")
        actions.append(reply("What can you do?"))
        return Outcome(template=template, facts=self.facts(turn, "greeting", assistant_capabilities=CAPABILITIES), actions=actions)

    async def on_general(self, turn: Turn) -> Outcome:
        text = turn.user.content
        if re.match(r"^(?:thanks?|thank you|thx|ty|cheers)", text, re.IGNORECASE):
            template = "You're welcome. I'm here if anything else comes up."
        elif re.match(r"^(?:bye|goodbye|see you|that's all|that is all)", text, re.IGNORECASE):
            template = "Okay. The conversation stays here if you need to pick it up again."
        elif turn.intent.confidence == "high":
            template = "Got it. Let me know what you'd like to look at next."
        else:
            template = ("I'm not sure what you'd like me to do with that. You can describe what users are seeing, ask about a device "
                        "(for example \"check SIN-RTR-01 routing\"), ask what a piece of evidence means, or ask me to diagnose the incident.")
        return Outcome(template=template, facts=self.facts(turn, "general_conversation", assistant_capabilities=CAPABILITIES))

    async def on_capabilities(self, turn: Turn) -> Outcome:
        lines = "\n".join(f"- {line}." for line in CAPABILITIES)
        role = ("" if can(turn.principal, Permission.RUN_DIAGNOSTICS)
                else "\n\nYour role can read the conversation and the evidence but can't run checks.")
        return Outcome(template=f"Here's how I can help:\n{lines}{role}",
                       facts=self.facts(turn, "capabilities", assistant_capabilities=CAPABILITIES),
                       actions=[reply("Explain the current diagnosis")] if self.diagnosis_line(turn.incident) else [])

    async def on_knowledge(self, turn: Turn) -> Outcome:
        context = turn.state.context
        query = KnowledgeQuery(text=turn.user.content[:4000], site_id=context.site_ids[0] if context.site_ids else None, limit=3)
        result = await run_in_threadpool(self.services.knowledge.search, query)
        documents = []
        for match in result.matches[:3]:
            try:
                record = self.services.knowledge.repository.get(match.record_id)
                excerpt = redact(render(record))[:700]
            except Exception:
                excerpt = ""
            documents.append({"record_id": match.record_id, "type": match.record_type.value, "title": match.title, "excerpt": excerpt})
        self.emit(turn, "knowledge.searched", {"query": turn.user.content[:200], "document_ids": [d["record_id"] for d in documents],
                                               "status": "guidance_only"})
        if documents:
            listed = "\n".join(f"- **{d['title']}** (`{d['record_id']}`)" for d in documents)
            template = (f"Here's what the knowledge base has on that. It's troubleshooting guidance, not evidence from this incident:\n{listed}"
                        "\n\nIf one of these fits, I can run the matching read-only checks when you ask.")
        else:
            template = ("I couldn't find a playbook or runbook that matches. If you tell me what users are seeing, I can help narrow it down "
                        "or run a specific read-only check.")
        return Outcome(template=template, facts=self.facts(turn, "knowledge_question", knowledge_base=documents,
                                                           knowledge_notice="Unverified guidance; not evidence."),
                       knowledge_searches=1)

    async def on_incident_query(self, turn: Turn) -> Outcome:
        incident = turn.incident
        if incident is None:
            return Outcome(template="This conversation isn't linked to an incident. Open one from the incidents list, or describe what users "
                                    "are seeing and I'll help from there.", facts=self.facts(turn, "incident_question"))
        text = turn.user.content.lower()
        record = incident.active_diagnosis
        actions: list[SuggestedAction] = []
        evidence: list[EvidenceReference] = []
        if re.search(r"severity|priority", text):
            template = (f"{incident.incident_id} is **{incident.severity.value}** severity ({incident.severity_source.value}) and priority "
                        f"**{incident.priority.value.upper()}** ({incident.priority_source.value}). Changing either is a human decision.")
        elif re.search(r"assign|owner|who", text):
            team = incident.assigned_team or "no team"
            template = f"{incident.incident_id} is assigned to {team}" + (f", owner {incident.assigned_owner}." if incident.assigned_owner else ".")
        elif re.search(r"escalat", text):
            open_items = [e for e in incident.escalations if e.status.value in ("recommended", "assigned")]
            template = (f"There are {len(incident.escalations)} escalations on {incident.incident_id}, {len(open_items)} still open."
                        if incident.escalations else f"Nothing has been escalated on {incident.incident_id} yet.")
        elif re.search(r"next|should (?:i|we)|recommend", text) and record is not None:
            checks = record.diagnosis.next_checks[:3]
            listed = "\n".join(f"- `{c.command}` on {c.device_id}: {c.purpose}" for c in checks)
            template = (f"Based on the current diagnosis, the next read-only checks are:\n{listed}\n\nA person still needs to confirm the "
                        "fault domain before it's recorded." if checks else "The current diagnosis has no further read-only checks queued.")
            actions.append(act("show_tab", "Show next checks", {"tab": "checks"}))
        elif record is not None:
            d = record.diagnosis
            supporting = [item for item in d.evidence if item.evidence_id in set(d.fault.supporting_evidence_ids)][:3]
            template = (f"{self.diagnosis_line(incident)}.\n\n" + "\n".join(bullet(item) for item in supporting)
                        + "\n\nThat's the stored diagnosis; I haven't re-run anything. It still needs a person to confirm the fault domain.")
            evidence = [reference(item, diagnosis_id=record.diagnosis_id) for item in supporting]
            actions.append(act("explain_evidence", f"Explain {supporting[0].evidence_id}" if supporting else "Explain the evidence",
                               {"evidence_ids": [supporting[0].evidence_id] if supporting else []}))
        else:
            template = (f"{incident.incident_id} ({incident.title}) is {incident.status.value} with {incident.severity.value} severity at "
                        f"{self.site_names(incident.site_ids)}. There's no diagnosis yet. Want me to run one?")
            actions = self.propose_diagnosis(turn)
        return Outcome(template=template, facts=self.facts(turn, "incident_question"), actions=actions, evidence=evidence)

    def missing_details(self, context: ConversationContext) -> list[str]:
        missing = []
        if not context.site_ids:
            missing.append("site")
        if not context.scope:
            missing.append("scope")
        if not context.services:
            missing.append("services")
        return missing

    def clarify(self, turn: Turn, missing: list[str], restate: str) -> Outcome:
        context = turn.state.context
        site = self.site_names(context.site_ids)
        questions = {
            "site": "Which site are the affected users at?",
            "scope": f"Is this hitting everyone at {site}, only some users, or a single person?",
            "services": "Which services are affected: internet access, internal apps like ERP or email, DNS, or Wi-Fi sign-in?",
        }
        asked = missing[:2]
        question = " ".join(questions[item] for item in asked)
        options = {"site": [self.index.site_names[s] for s in sorted(self.index.site_names)],
                   "scope": ["Everyone at the site", "Only some users", "Just one user"],
                   "services": ["Internet", "Internal apps (ERP, email)", "DNS / name resolution", "Wi-Fi sign-in"]}[asked[0]]
        clarification = Clarification(question=question, missing=missing, options=options)
        context.pending_clarification = PendingClarification(for_intent=Intent.SYMPTOM_REPORT, question=question, missing=missing)
        actions = [act("full_diagnosis", "Diagnose now", tools=True)] if self.can_diagnose(turn) and context.site_ids else []
        if context.focus_device_id and can(turn.principal, Permission.RUN_DIAGNOSTICS) and context.scenario_id:
            device = context.focus_device_id
            actions.append(act("targeted_check", f"Check {device} availability",
                               {"tool": "check_device_availability", "arguments": {"device_id": device}}, tools=True))
        template = f"{restate} Before I run anything, {question[0].lower()}{question[1:]}"
        return Outcome(template=template, facts=self.facts(turn, "clarification_needed", clarification=clarification.model_dump()),
                       clarification=clarification, actions=actions)

    def restatement(self, turn: Turn) -> str:
        context = turn.state.context
        who = f"users at {self.site_names(context.site_ids)}" if context.site_ids else "users"
        if context.scope:
            who = f"{SCOPE_TEXT[context.scope]} at {self.site_names(context.site_ids)}" if context.site_ids else SCOPE_TEXT[context.scope]
        what = ", ".join(context.symptoms[:3]) or "a problem"
        named = [s.replace("_", " ") for s in context.services[:3] if s.replace("_", " ") not in what]
        services = f" affecting {', '.join(named)}" if named else ""
        return f"Got it: {who} are seeing {what}{services}."

    def ready_to_diagnose(self, turn: Turn) -> Outcome:
        context = turn.state.context
        context.pending_clarification = None
        actions = self.propose_diagnosis(turn)
        timeframe = f" since {context.timeframe}" if context.timeframe and not context.timeframe.lower().startswith("since") else (
            f" {context.timeframe}" if context.timeframe else "")
        if actions:
            template = (f"{self.restatement(turn)[:-1]}{timeframe}. That's enough to start. Want me to run a full diagnosis? It only "
                        f"uses read-only checks, at most {MAX_TOOL_CALLS} tool calls.")
        else:
            template = (f"{self.restatement(turn)[:-1]}{timeframe}. "
                        + ("Your role can't run diagnostics, so an operator would need to start the investigation."
                           if not can(turn.principal, Permission.RUN_DIAGNOSTICS)
                           else "This conversation isn't linked to a telemetry dataset, so I can't run checks yet."))
        return Outcome(template=template, facts=self.facts(turn, "ready_to_diagnose", proposal="Run a full read-only diagnosis"
                                                           if actions else None), actions=actions)

    async def on_symptom_report(self, turn: Turn) -> Outcome:
        missing = self.missing_details(turn.state.context)
        if missing:
            return self.clarify(turn, missing, self.restatement(turn))
        return self.ready_to_diagnose(turn)

    async def on_clarification(self, turn: Turn) -> Outcome:
        context = turn.state.context
        pending = context.pending_clarification
        if pending is not None and pending.for_intent == Intent.TARGETED_DIAGNOSTIC:
            entities = turn.intent.entities
            if pending.device_id and not entities.device_ids:
                entities.device_ids = [pending.device_id]
            calls, missing, _ = Planner(self.index).plan(turn.user.content, pending.topics, entities, context)
            if calls:
                context.pending_clarification = None
                turn.intent.planned_calls = calls
                turn.intent.missing = missing
                return await self.on_targeted_diagnostic(turn)
        if pending is None and not (turn.intent.entities.scope or turn.intent.entities.timeframe):
            return await self.on_general(turn)
        missing = self.missing_details(context)
        if missing:
            return self.clarify(turn, missing, "Thanks.")
        return self.ready_to_diagnose(turn)

    async def on_status(self, turn: Turn) -> Outcome:
        state = turn.state
        latest = next(reversed(state.investigations.values()), None)
        parts = ["Nothing is running right now."]
        if latest is not None:
            summary = latest.summary()
            kind = "full diagnosis" if latest.kind == "full_diagnosis" else "targeted check"
            parts.append(f"The last {kind} ({latest.investigation_id}) {summary.status} with {summary.tool_calls} "
                         f"tool call{'s' if summary.tool_calls != 1 else ''} and {summary.evidence_count} evidence "
                         f"item{'s' if summary.evidence_count != 1 else ''}"
                         + (f", pointing to {FAULT_LABEL.get(summary.fault_domain, summary.fault_domain)} ({summary.confidence} confidence)"
                            if summary.fault_domain else "") + ".")
        if turn.incident is not None:
            parts.append(f"{turn.incident.incident_id} is {turn.incident.status.value}"
                         + (f" and the fault domain is confirmed as {turn.incident.classification.confirmed_fault_domain.value}."
                            if turn.incident.classification.confirmed_fault_domain else "; the fault domain isn't confirmed yet."))
        if state.context.pending_action is not None:
            parts.append("I'm waiting for your go-ahead on the full diagnosis I suggested.")
        if state.context.pending_clarification is not None:
            parts.append(f"I'm still waiting on: {state.context.pending_clarification.question}")
        return Outcome(template=" ".join(parts), facts=self.facts(turn, "status", investigations=[
            i.summary().model_dump(mode="json") for i in list(state.investigations.values())[-3:]]))

    async def on_human_action(self, turn: Turn) -> Outcome:
        action = turn.intent.human_action or "confirm"
        incident = turn.incident
        if action == "remediate":
            checks = incident.active_diagnosis.diagnosis.next_checks[:2] if incident and incident.active_diagnosis else []
            listed = "".join(f"\n- `{c.command}` on {c.device_id}" for c in checks)
            template = ("I can't make changes. I only have read-only access to the synthetic telemetry, and any fix has to go through "
                        "your change process and be carried out by an engineer."
                        + (f" What I can do is help verify, for example:{listed}" if listed else
                           " I can run read-only checks or a full diagnosis to support the change request."))
            actions = [act("open_human_action", "Escalate", {"action": "escalate"}, human=True,
                           allowed=can(turn.principal, Permission.UPDATE_INCIDENTS))] if incident else []
            return Outcome(template=template, facts=self.facts(turn, "remediation_refused"), actions=actions)
        if incident is None:
            return Outcome(template="This conversation isn't linked to an incident, so there's nothing to record that on.",
                           facts=self.facts(turn, "human_action_without_incident"))
        if action == "save":
            return self.offer_attach(turn)
        label, permission, button = HUMAN_ACTIONS[action]
        allowed = can(turn.principal, permission)
        confirmation = HumanConfirmation(action=action, label=label, reason=f"{label} is a human decision; the assistant never records it",
                                         permission=permission.value, allowed=allowed)
        self.emit(turn, "human_confirmation.required", confirmation.model_dump(mode="json"))
        context_line = ""
        if action == "confirm":
            context_line = f" {self.diagnosis_line(incident)}." if incident.active_diagnosis else " There's no diagnosis to confirm yet."
        how = (f"Use **{button}** to open the form; nothing is recorded until you submit it." if allowed
               else f"Your role can't do this ({permission.value} is required), so it needs someone like an incident manager.")
        template = f"{label} is a human decision, so I won't do it myself.{context_line} {how}"
        actions = [act("open_human_action", button, {"action": action}, human=True, allowed=allowed,
                       reason=None if allowed else f"Requires {permission.value}")]
        return Outcome(template=template, facts=self.facts(turn, "human_action_requested", human_action=label, allowed=allowed),
                       actions=actions, confirmations=[confirmation])

    def offer_attach(self, turn: Turn) -> Outcome:
        state = turn.state
        incident = turn.incident
        latest = next((i for i in reversed(state.investigations.values()) if i.kind == "full_diagnosis" and i.report is not None), None)
        if latest is None:
            return Outcome(template="There's no diagnosis from this conversation to save yet. Ask me to diagnose the incident first.",
                           facts=self.facts(turn, "nothing_to_save"))
        if latest.attached_diagnosis_id:
            return Outcome(template=f"That diagnosis is already saved to {incident.incident_id} as {latest.attached_diagnosis_id}.",
                           facts=self.facts(turn, "already_saved", diagnosis_id=latest.attached_diagnosis_id))
        allowed, reason = self.attach_allowed(turn.principal, incident)
        confirmation = HumanConfirmation(action="attach_investigation", label=f"Save the diagnosis to {incident.incident_id}",
                                         reason="Saving changes the incident record, so it needs your explicit approval",
                                         permission=Permission.RUN_DIAGNOSTICS.value, allowed=allowed)
        self.emit(turn, "human_confirmation.required", confirmation.model_dump(mode="json"))
        template = (f"Saving {latest.investigation_id} to {incident.incident_id} changes the incident record, so I need you to approve it. "
                    + ("Use **Save to incident** to confirm." if allowed else f"It can't be saved right now: {reason}."))
        return Outcome(template=template, facts=self.facts(turn, "save_requested", investigation_id=latest.investigation_id),
                       confirmations=[confirmation],
                       actions=[act("attach_investigation", "Save to incident", {"investigation_id": latest.investigation_id,
                                                                                 "incident_id": incident.incident_id},
                                    human=True, allowed=allowed, reason=reason)])

    @staticmethod
    def attach_allowed(principal: Principal, incident: Incident) -> tuple[bool, str | None]:
        if not can(principal, Permission.RUN_DIAGNOSTICS):
            return False, "your role can't attach diagnoses"
        if not incident.dataset_scenario_id:
            return False, "the incident isn't linked to a telemetry dataset"
        if incident.status.value not in SAVEABLE:
            return False, f"the incident is {incident.status.value}"
        return True, None

    async def on_cancellation(self, turn: Turn) -> Outcome:
        context = turn.state.context
        if context.pending_action is not None or context.pending_clarification is not None:
            context.pending_action = None
            context.pending_clarification = None
            return Outcome(template="Okay, I've dropped that. Nothing ran and nothing was changed.", facts=self.facts(turn, "cancelled"))
        return Outcome(template="There's nothing running to cancel.", facts=self.facts(turn, "nothing_to_cancel"))

    async def on_decline(self, turn: Turn) -> Outcome:
        turn.state.context.pending_action = None
        return Outcome(template="Okay, I won't run it. Tell me when you're ready, or ask about anything else.",
                       facts=self.facts(turn, "proposal_declined"))

    async def on_confirmation(self, turn: Turn) -> Outcome:
        pending = turn.state.context.pending_action
        turn.state.context.pending_action = None
        if pending is None:
            return await self.on_general(turn)
        if pending.kind == "targeted_check":
            turn.intent.planned_calls = list(pending.calls)
            return await self.on_targeted_diagnostic(turn)
        turn.intent.rerun = True
        return await self.on_full_diagnosis(turn)

    # ---------- evidence explanation (reuses stored evidence; never re-runs) ----------

    def evidence_source(self, turn: Turn, wanted: list[str]) -> tuple[list[EvidenceItem], str | None, str | None, Diagnosis | None]:
        state = turn.state
        for investigation in reversed(state.investigations.values()):
            ids = {item.evidence_id for item in investigation.evidence}
            if investigation.evidence and (not wanted and investigation.kind == "full_diagnosis" or wanted and set(wanted) & ids):
                return investigation.evidence, investigation.investigation_id, None, state.diagnoses.get(investigation.investigation_id)
        record = turn.incident.active_diagnosis if turn.incident else None
        if record is not None:
            return record.diagnosis.evidence, None, record.diagnosis_id, record.diagnosis
        latest = next((i for i in reversed(state.investigations.values()) if i.evidence), None)
        if latest is not None:
            return latest.evidence, latest.investigation_id, None, state.diagnoses.get(latest.investigation_id)
        return [], None, None, None

    @staticmethod
    def role_of(item: EvidenceItem, diagnosis: Diagnosis | None) -> str:
        if diagnosis is None:
            return "context from a targeted check; not tied to a hypothesis"
        if item.evidence_id in diagnosis.fault.supporting_evidence_ids:
            return "supports the current hypothesis"
        if item.evidence_id in diagnosis.fault.contradictory_evidence_ids:
            return "contradicts the current hypothesis"
        for alternative in diagnosis.alternatives:
            if item.evidence_id in alternative.supporting_evidence_ids:
                return f"supports the alternative hypothesis ({FAULT_LABEL.get(alternative.fault_domain.value)})"
        return "collected during the diagnosis but not cited by the hypothesis"

    async def on_evidence_explanation(self, turn: Turn) -> Outcome:
        wanted = turn.intent.entities.evidence_ids
        items, investigation_id, diagnosis_id, diagnosis = self.evidence_source(turn, wanted)
        source = (f"the investigation I ran in this conversation ({investigation_id})" if investigation_id
                  else f"the incident's current diagnosis ({diagnosis_id})")
        if not items:
            actions = self.propose_diagnosis(turn)
            return Outcome(template="There's no evidence to explain yet: no diagnosis has been run"
                                    + (" here or on the incident." if turn.incident else " in this conversation.")
                                    + (" Want me to run one?" if actions else ""),
                           facts=self.facts(turn, "no_evidence", proposal="Run a full read-only diagnosis" if actions else None),
                           actions=actions)
        by_id = {item.evidence_id: item for item in items}
        refs = lambda chosen: [reference(i, investigation_id, diagnosis_id) for i in chosen]  # noqa: E731
        if wanted:
            found = [by_id[e] for e in wanted if e in by_id]
            unknown = [e for e in wanted if e not in by_id]
            parts = []
            for item in found:
                kind, meaning = EVIDENCE_KIND[item.evidence_type]
                on = f" on {item.device_id}" if item.device_id else ""
                when = f" at {item.timestamp.strftime('%Y-%m-%d %H:%M UTC')}" if item.timestamp else ""
                parts.append(f"**{item.evidence_id}** is {kind} from {TOOL_LABEL.get(item.tool, item.tool).lower()}{on} "
                             f"(call {item.call_id}{when}): \"{item.summary}\". {meaning} It {self.role_of(item, diagnosis)}.")
            if unknown:
                parts.append(f"I don't have {', '.join(unknown)} in {source}; it has {items[0].evidence_id} to {items[-1].evidence_id}.")
            template = "\n\n".join(parts) + f"\n\nThis comes from {source}; I didn't re-run anything."
            chosen = found
        else:
            if diagnosis is None:
                chosen = items[:5]
                template = f"Here's the evidence from {source}:\n" + "\n".join(bullet(i) for i in chosen)
            else:
                supporting = [by_id[e] for e in diagnosis.fault.supporting_evidence_ids if e in by_id][:5]
                chosen = supporting or items[:5]
                fault = diagnosis.fault
                template = (f"The hypothesis is **{fault.root_cause}** ({FAULT_LABEL.get(fault.fault_domain.value)}, "
                            f"{diagnosis.confidence.level.value.replace('_', ' ')} confidence). {fault.reasoning}\n\n"
                            + "\n".join(bullet(i) for i in chosen)
                            + f"\n\n{diagnosis.confidence.explanation} This comes from {source}; I didn't re-run anything.")
        facts = self.facts(turn, "evidence_explanation", evidence_source=source,
                           evidence=[evidence_fact(i, self.role_of(i, diagnosis)) for i in chosen[:MAX_FACT_EVIDENCE]],
                           hypothesis={"root_cause": diagnosis.fault.root_cause, "fault_domain": diagnosis.fault.fault_domain.value,
                                       "reasoning": diagnosis.fault.reasoning, "confidence": diagnosis.confidence.level.value,
                                       "confidence_explanation": diagnosis.confidence.explanation} if diagnosis else None,
                           available_evidence_range=f"{items[0].evidence_id}-{items[-1].evidence_id}")
        facts["evidence_ids"] = sorted(set(facts["evidence_ids"]) | {i.evidence_id for i in chosen})
        actions = [act("explain_evidence", f"Explain {i.evidence_id}", {"evidence_ids": [i.evidence_id]})
                   for i in items if i not in chosen][:2]
        return Outcome(template=template, facts=facts, evidence=refs(chosen), actions=actions)

    # ---------- tool-running handlers ----------

    def deny_tools(self, turn: Turn) -> Outcome | None:
        if not can(turn.principal, Permission.RUN_DIAGNOSTICS):
            roles = ", ".join(role.value for role in turn.principal.roles)
            return Outcome(template=f"Your role ({roles}) can read the conversation and the evidence, but running diagnostic checks needs "
                                    "the run_diagnostics permission. An operator or incident manager can run it.",
                           facts=self.facts(turn, "permission_denied", permission="run_diagnostics"), use_model=False)
        if not turn.state.context.scenario_id:
            return Outcome(template="This conversation isn't linked to a telemetry dataset, so there's nothing for me to check. Open the "
                                    "assistant from an incident that has demo telemetry, or start a conversation with a scenario.",
                           facts=self.facts(turn, "no_dataset"), use_model=False)
        return None

    def start_investigation(self, turn: Turn, kind: Literal["full_diagnosis", "targeted_check"],
                            mode: Literal["agent", "rule_based", "direct"], model: str | None = None) -> Investigation:
        context = turn.state.context
        investigation = Investigation(investigation_id=new_id("INV", 6), conversation_id=turn.state.conversation_id,
                                      turn_id=turn.handle.turn_id, kind=kind, status="running", scenario_id=context.scenario_id,
                                      site_ids=list(context.site_ids), device_ids=list(context.device_ids), mode=mode, model=model,
                                      started_at=now(), budget_limit=MAX_TOOL_CALLS)
        turn.state.add_investigation(investigation)
        turn.handle.investigation_id = investigation.investigation_id
        turn.observer = ProgressObserver(self, turn, investigation, asyncio.get_running_loop())
        context.last_investigation_id = investigation.investigation_id
        return investigation

    def close_investigation(self, turn: Turn, investigation: Investigation, status: str) -> None:
        if turn.observer is not None:
            turn.observer.closed = True
        investigation.status = status
        investigation.finished_at = now()
        investigation.duration_ms = int((investigation.finished_at - investigation.started_at).total_seconds() * 1000)
        self.emit(turn, f"investigation.{'failed' if status == 'failed' else 'completed'}",
                  {"investigation_id": investigation.investigation_id, "summary": investigation.summary().model_dump(mode="json")})

    @staticmethod
    def normalized(call: PlannedCall) -> dict[str, Any] | None:
        try:
            return REGISTRY[call.tool].arguments.model_validate(call.arguments).model_dump(exclude_none=True)
        except Exception:
            return None

    def previous_step(self, turn: Turn, call: PlannedCall) -> tuple[Investigation, ToolStep] | None:
        arguments = self.normalized(call)
        if arguments is None:
            return None
        for investigation in reversed(turn.state.investigations.values()):
            for step in investigation.steps:
                if step.tool == call.tool and step.arguments == arguments and step.status == "executed" and step.call_id:
                    return investigation, step
        return None

    def targeted_clarification(self, turn: Turn, missing: list[str]) -> Outcome:
        context = turn.state.context
        gap = missing[0]
        topic, _, rest = gap.partition(":")
        what, _, device = rest.partition(":")
        if what == "interface":
            interfaces = self.index.interfaces.get(device, [])[:5]
            question = (f"Which interface on {device} should I analyse for {TOPIC_LABEL[topic]}? "
                        + ", ".join(f"{i.name} ({i.description})" if i.description else i.name for i in interfaces) + ".")
            options = [i.name for i in interfaces]
        elif what == "device":
            sites = context.site_ids or sorted(self.index.site_names)
            options = [d.device_id for d in self.index.topology.devices if d.site_id in sites][:6]
            question = f"Which device should I check for {TOPIC_LABEL[topic]}? For example {', '.join(options[:3])}."
        elif what == "site":
            options = [self.index.site_names[s] for s in sorted(self.index.site_names)]
            question = f"Which site should I check for {TOPIC_LABEL[topic]}?"
        else:
            options = []
            question = "Between which two points should I check reachability? For example \"from SIN-SW-01 to DC1-SRV-APP-01\"."
        context.pending_clarification = PendingClarification(for_intent=Intent.TARGETED_DIAGNOSTIC, question=question, missing=missing,
                                                             topics=[topic], device_id=device or None)
        clarification = Clarification(question=question, missing=missing, options=options)
        return Outcome(template=question, facts=self.facts(turn, "clarification_needed", clarification=clarification.model_dump()),
                       clarification=clarification)

    async def on_targeted_diagnostic(self, turn: Turn) -> Outcome:
        denied = self.deny_tools(turn)
        if denied is not None:
            return denied
        intent = turn.intent
        calls = [c for c in intent.planned_calls if c.tool in REGISTRY][:4]
        if not calls:
            if intent.missing:
                return self.targeted_clarification(turn, intent.missing)
            return Outcome(template="I couldn't work out which check you meant. Name the device and what to look at, for example "
                                    "\"check SIN-RTR-01 routing\".", facts=self.facts(turn, "unclear_check"))
        reused = {}
        if not intent.rerun:
            for call in calls:
                found = self.previous_step(turn, call)
                if found is not None:
                    reused[id(call)] = found
        fresh = [call for call in calls if id(call) not in reused]
        context = turn.state.context
        devices = [c.arguments.get("device_id") for c in calls if c.arguments.get("device_id") in self.index.devices]
        if devices:
            context.focus_device_id = devices[0]
        investigation = None
        records: list[ToolCallRecord] = []
        if fresh:
            investigation = self.start_investigation(turn, "targeted_check", "direct")
            self.emit(turn, "investigation.started", {
                "investigation_id": investigation.investigation_id, "kind": "targeted_check", "mode": "direct",
                "planned": [{"tool": c.tool, "label": TOOL_LABEL.get(c.tool, c.tool), "arguments": c.arguments, "reason": c.reason}
                            for c in fresh], "budget_limit": MAX_TOOL_CALLS})
            executor = ToolExecutor(context.scenario_id, max_calls=MAX_TOOL_CALLS, observer=turn.observer,
                                    cancel_event=turn.handle.cancel_event)
            for call in fresh:
                records.append(await asyncio.to_thread(executor.execute, call.tool, call.arguments))
            investigation.budget_used = executor.requests
            investigation.evidence = build_catalog(executor.records)
            failed = any(not r.succeeded for r in records)
            self.emit(turn, "evidence.correlated", {
                "investigation_id": investigation.investigation_id,
                "evidence": [reference(i, investigation.investigation_id).model_dump(mode="json") for i in investigation.evidence[:20]]})
            self.close_investigation(turn, investigation, "partial" if failed else "completed")
        lines: list[str] = []
        evidence_items: list[tuple[EvidenceItem, str]] = []
        summaries: dict[int, str] = {}
        for call in calls:
            arguments = call.arguments
            target = arguments.get("device_id") or arguments.get("site_id") or (
                f"{arguments.get('source')} -> {arguments.get('destination')}" if "source" in arguments else "the site")
            if id(call) in reused:
                previous, step = reused[id(call)]
                items = [i for i in previous.evidence if i.evidence_id in step.evidence_ids]
                source_id, ok = previous.investigation_id, True
                summaries[id(call)] = step.summary or "completed"
                lines.append(f"**{TOOL_LABEL[call.tool]} for {target}**: I already ran this in {previous.investigation_id} "
                             f"({step.call_id}), so I'm reusing that result: {step.summary}.")
            else:
                record = next(r for r, c in zip(records, fresh) if c is call)
                items = [i for i in investigation.evidence if i.call_id == record.call_id]
                source_id, ok = investigation.investigation_id, record.succeeded
                summaries[id(call)] = digest(record)
                lines.append(f"**{TOOL_LABEL[call.tool]} for {target}** ({record.call_id}): {summaries[id(call)]}.")
            evidence_items += [(i, source_id) for i in items]
            findings = [i for i in items if i.evidence_type != EvidenceType.RECORD]
            lines += [bullet(i) for i in findings[:4]]
            if not findings and ok:
                lines.append("- No fault findings in this result.")
        if intent.missing:
            lines.append(f"I skipped part of the request because I need more detail: {self.targeted_clarification(turn, intent.missing).template}")
        lines.append("These are read-only reads of the synthetic telemetry; nothing was changed.")
        chosen = evidence_items[:MAX_FACT_EVIDENCE]
        facts = self.facts(turn, "targeted_check", tools_ran_this_turn=bool(fresh), checks=[
            {"tool": c.tool, "label": TOOL_LABEL.get(c.tool), "arguments": c.arguments,
             "reused_from": reused[id(c)][0].investigation_id if id(c) in reused else None, "summary": summaries[id(c)]}
            for c in calls], evidence=[evidence_fact(i) for i, _ in chosen])
        facts["evidence_ids"] = sorted(set(facts["evidence_ids"]) | {i.evidence_id for i, _ in chosen})
        actions = []
        if chosen:
            actions.append(act("explain_evidence", f"Explain {chosen[0][0].evidence_id}", {"evidence_ids": [chosen[0][0].evidence_id]}))
        if self.can_diagnose(turn):
            actions.append(act("full_diagnosis", "Run full diagnosis", tools=True))
        return Outcome(template="\n".join(lines), facts=facts, investigation=investigation,
                       evidence=[reference(i, inv) for i, inv in chosen], actions=actions)

    def diagnosis_report(self, turn: Turn) -> str:
        context = turn.state.context
        parts = list(context.notes[-4:])
        if context.scope:
            parts.append(SCOPE_REPORT[context.scope])
        if context.services:
            parts.append(f"Affected services: {', '.join(context.services)}.")
        if turn.incident is not None:
            parts.append(f"Incident {turn.incident.incident_id}: {turn.incident.title}. {turn.incident.description}")
        if not parts:
            parts.append(f"Users at {self.site_names(context.site_ids)} report a network problem.")
        return redact(" ".join(parts))[:3900]

    async def on_full_diagnosis(self, turn: Turn) -> Outcome:
        denied = self.deny_tools(turn)
        if denied is not None:
            return denied
        state = turn.state
        context = state.context
        if not context.site_ids:
            clarification = Clarification(question="Which site should I diagnose?", missing=["site"],
                                          options=[self.index.site_names[s] for s in sorted(self.index.site_names)])
            context.pending_clarification = PendingClarification(for_intent=Intent.FULL_DIAGNOSIS, question=clarification.question,
                                                                 missing=["site"])
            return Outcome(template="Which site should I diagnose? I need at least the site before I can pick the right checks.",
                           facts=self.facts(turn, "clarification_needed", clarification=clarification.model_dump()),
                           clarification=clarification)
        report_text = self.diagnosis_report(turn)
        fingerprint = hashlib.sha256(f"{context.scenario_id}|{','.join(context.site_ids)}|{report_text}".encode()).hexdigest()
        if not turn.intent.rerun:
            for investigation_id, previous_print in reversed(state.fingerprints.items()):
                previous = state.investigations.get(investigation_id)
                if previous_print == fingerprint and previous is not None and previous.status in ("completed", "partial"):
                    report = previous.report
                    template = (f"I already ran a full diagnosis on exactly this ({investigation_id}), and nothing new has come up since. "
                                f"It pointed to **{report.root_cause_hypothesis.statement}** "
                                f"({report.confidence.level.value.replace('_', ' ')} confidence). Say \"run it again\" if you want a fresh run.")
                    return Outcome(template=template, facts=self.facts(turn, "diagnosis_reused", investigation=previous.summary().model_dump(
                        mode="json")), actions=[act("full_diagnosis", "Run it again", tools=True)])
        limiter = self.services.agent_runs
        if not limiter.acquire():
            return Outcome(template="The diagnosis engine is busy with other runs right now. Try again in a moment.",
                           facts=self.facts(turn, "busy"), status="failed", use_model=False)
        resources = self.services.agent
        mode: Literal["agent", "rule_based"] = "agent" if resources.model is not None and state.mode == "auto" else "rule_based"
        investigation = self.start_investigation(turn, "full_diagnosis", mode, resources.model.model if mode == "agent" else None)
        state.fingerprints[investigation.investigation_id] = fingerprint
        self.emit(turn, "investigation.started", {
            "investigation_id": investigation.investigation_id, "kind": "full_diagnosis", "mode": mode, "model": investigation.model,
            "scenario_id": context.scenario_id, "site_ids": context.site_ids, "budget_limit": MAX_TOOL_CALLS})
        services = [PathService(s) for s in context.services if s in PathService._value2member_map_]
        arguments = dict(scenario_id=context.scenario_id, report=report_text, site_ids=context.site_ids[:5],
                         device_ids=context.device_ids[:20], services=services, incident_id=context.incident_id,
                         observer=turn.observer, cancel_event=turn.handle.cancel_event)
        retriever = self.services.knowledge.diagnosis_retriever()
        try:
            if mode == "agent":
                async with resources.http_client() as client:
                    agent = DiagnosisAgent(settings=self.services.settings, retriever=retriever, http_client=client)
                    run = await agent.arun(**arguments)
            else:
                agent = DiagnosisAgent(settings=self.services.settings, retriever=retriever, rule_based=True)
                run = await asyncio.to_thread(asyncio.run, agent.arun(**arguments))
        except DiagnosisRequestError as exc:
            investigation.error = redact(str(exc))
            self.close_investigation(turn, investigation, "failed")
            return Outcome(template=f"I couldn't start the diagnosis: {investigation.error}.", facts=self.facts(turn, "diagnosis_failed"),
                           investigation=investigation, status="failed", use_model=False)
        finally:
            limiter.release()
        report = await run_in_threadpool(build_report, run)
        investigation.report = report
        investigation.evidence = build_catalog(run.records)
        investigation.budget_used = run.budget.attempts
        investigation.fallback_used = mode == "agent" and not run.agent_completed
        investigation.knowledge_documents = sorted(run.budget.documents)
        state.diagnoses[investigation.investigation_id] = run.diagnosis
        status = {"completed": "completed", "failed": "failed"}.get(run.diagnosis.incident.status.value, "partial")
        self.emit(turn, "evidence.correlated", {
            "investigation_id": investigation.investigation_id, "fault_domain": report.fault_domain.value,
            "confidence": report.confidence.level.value, "root_cause": report.root_cause_hypothesis.statement,
            "supporting_evidence_ids": run.diagnosis.fault.supporting_evidence_ids,
            "evidence": [reference(i, investigation.investigation_id).model_dump(mode="json") for i in report.evidence_references[:20]]})
        self.close_investigation(turn, investigation, status)
        return self.diagnosis_outcome(turn, investigation, run.diagnosis)

    def diagnosis_outcome(self, turn: Turn, investigation: Investigation, diagnosis: Diagnosis) -> Outcome:
        report = investigation.report
        incident = turn.incident
        by_id = {item.evidence_id: item for item in investigation.evidence}
        supporting = [by_id[e] for e in diagnosis.fault.supporting_evidence_ids if e in by_id][:4]
        if not supporting:
            supporting = [by_id[f.evidence_id] for f in report.verified_facts if f.evidence_id in by_id][:4]
        calls = investigation.summary().tool_calls
        how = f"from {calls} read-only tool call{'s' if calls != 1 else ''}"
        if investigation.mode == "rule_based":
            how += ", using the rule-based planner because no model is in use"
        confidence = report.confidence.level.value.replace("_", " ")
        capped = f" (capped from {report.confidence.capped_from.value})" if report.confidence.capped_from else ""
        lines = [f"Here's what I found {how}:", "",
                 f"**{report.root_cause_hypothesis.statement}**",
                 f"Fault domain: {FAULT_LABEL.get(report.fault_domain.value)}. Confidence: {confidence}{capped}.", ""]
        if supporting:
            lines += ["Key evidence:"] + [bullet(i) for i in supporting] + [""]
        if report.discrepancies:
            lines += [f"Watch out: {report.discrepancies[0]}", ""]
        if report.recommended_next_checks:
            check = report.recommended_next_checks[0]
            lines += [f"Next read-only check: `{check.command}` on {check.device_id} ({check.purpose}).", ""]
        unknowns = [item for item in report.missing_evidence if not item.startswith("The hypothesis requires human")]
        if unknowns:
            lines += [f"Still unknown: {unknowns[0]}", ""]
        saved = f", and it isn't saved to {incident.incident_id}" if incident else ""
        footer = f"This is a hypothesis for a person to review. Nothing has been changed or recorded{saved}."
        if investigation.fallback_used:
            footer = "The model didn't finish its own diagnosis, so this result comes from the rule-based planner. " + footer
        lines.append(footer)
        actions: list[SuggestedAction] = []
        confirmations: list[HumanConfirmation] = []
        if supporting:
            actions.append(act("explain_evidence", f"Explain {supporting[0].evidence_id}", {"evidence_ids": [supporting[0].evidence_id]}))
        if incident is not None and investigation.status != "failed":
            allowed, reason = self.attach_allowed(turn.principal, incident)
            confirmations.append(HumanConfirmation(action="attach_investigation", label=f"Save the diagnosis to {incident.incident_id}",
                                                   reason="Saving changes the incident record, so it needs your explicit approval",
                                                   permission=Permission.RUN_DIAGNOSTICS.value, allowed=allowed))
            actions.append(act("attach_investigation", "Save to incident", {"investigation_id": investigation.investigation_id,
                                                                           "incident_id": incident.incident_id},
                               human=True, allowed=allowed, reason=reason))
            confirm_allowed = can(turn.principal, Permission.CONFIRM_CLASSIFICATION)
            confirmations.append(HumanConfirmation(action="confirm", label="Confirm the fault domain",
                                                   reason="Only a person can record the classification",
                                                   permission=Permission.CONFIRM_CLASSIFICATION.value, allowed=confirm_allowed))
            actions.append(act("open_human_action", "Review and confirm", {"action": "confirm"}, human=True, allowed=confirm_allowed,
                               reason=None if confirm_allowed else "Requires confirm_classification"))
        for confirmation in confirmations:
            self.emit(turn, "human_confirmation.required", confirmation.model_dump(mode="json"))
        if report.recommended_next_checks:
            actions.append(act("show_tab", "Show next checks", {"tab": "checks"}))
        facts = self.facts(turn, "full_diagnosis", tools_ran_this_turn=True, diagnosis={
            "investigation_id": investigation.investigation_id, "status": investigation.status, "method": report.method.value,
            "mode": investigation.mode, "fallback_used": investigation.fallback_used, "tool_calls": calls,
            "root_cause": report.root_cause_hypothesis.statement, "fault_domain": report.fault_domain.value,
            "confidence": report.confidence.level.value,
            "capped_from": report.confidence.capped_from.value if report.confidence.capped_from else None,
            "confidence_explanation": report.confidence.explanation, "reasoning": report.root_cause_hypothesis.reasoning,
            "discrepancies": report.discrepancies[:3], "missing_evidence": [m for m in report.missing_evidence
                                 if not m.startswith("The hypothesis requires human")][:3],
            "next_checks": [{"device_id": c.device_id, "command": c.command, "purpose": c.purpose}
                            for c in report.recommended_next_checks[:3]],
            "escalation_recommendation": {"team": report.escalation.team, "priority": report.escalation.priority,
                                          "delivery_status": "not_sent"},
            "saved_to_incident": False,
        }, evidence=[evidence_fact(i, "supports the hypothesis") for i in supporting])
        facts["evidence_ids"] = sorted(set(facts["evidence_ids"]) | {i.evidence_id for i in investigation.evidence})
        return Outcome(template="\n".join(lines), facts=facts, investigation=investigation, confirmations=confirmations,
                       evidence=[reference(i, investigation.investigation_id) for i in supporting], actions=actions, footer=footer)

    # ---------- human-approved write ----------

    async def attach(self, state: ConversationState, principal: Principal, investigation_id: str, expected_version: int):
        from app.api.records import expected
        investigation = state.investigations.get(investigation_id)
        diagnosis = state.diagnoses.get(investigation_id)
        if investigation is None or diagnosis is None or investigation.kind != "full_diagnosis":
            raise AppError("Investigation not found or it is not a full diagnosis", code="NOT_FOUND", status_code=404)
        if investigation.attached_diagnosis_id:
            raise AppError(f"Already saved as {investigation.attached_diagnosis_id}", code="ALREADY_ATTACHED", status_code=409)
        if investigation.status not in ("completed", "partial"):
            raise AppError("Only a finished diagnosis can be saved", code="VALIDATION_ERROR", status_code=422)
        incident_id = state.context.incident_id
        if not incident_id:
            raise AppError("This conversation is not linked to an incident", code="VALIDATION_ERROR", status_code=422)
        secured = self.services.secured_incidents

        def write():
            with expected(secured, principal, incident_id, expected_version):
                return secured.associate_diagnosis(principal, incident_id, diagnosis)
        updated = await run_in_threadpool(write)
        investigation.attached_diagnosis_id = updated.active_diagnosis_id
        investigation.attached_incident_version = updated.version
        self.emit_state(state, "investigation.attached", {"investigation_id": investigation_id, "incident_id": incident_id,
                                                          "diagnosis_id": updated.active_diagnosis_id, "version": updated.version,
                                                          "approved_by": principal.subject})
        return updated
