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
from types import SimpleNamespace
from typing import Any, Literal

from starlette.concurrency import run_in_threadpool

from app.agent import DiagnosisAgent, build_report
from app.agent.tools import KNOWLEDGE_TOOL
from app.conversation import assist
from app.conversation.composer import ReplyComposer, grounding_issues
from app.conversation.concepts import comparison, explain_concepts
from app.conversation.digests import digest
from app.conversation.entities import TopologyIndex, topology_index
from app.conversation.intents import AFFIRM, TOPIC_LABEL, TOPIC_TOOL, USER_REPORT, WHAT_HAPPENED, Planner, classify, human_action_in
from app.conversation.plain import FAULT_PLAIN, HEALTHY, Namer, capital, first_mention, ids_text, join, problem as problem_of, sentence
from app.conversation.plain import lower_first as plain_lower
from app.conversation.models import (
    Attachment,
    Clarification,
    ConversationContext,
    EvidenceReference,
    ExecutionSummary,
    GeneratedBy,
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
from app.incidents.models import Incident, IncidentFilter
from app.knowledge.retrieval import KnowledgeQuery, render
from app.network.models import DeviceRole, PathService
from app.network.repository import load_scenario, scenario_exists
from app.protocols.analysis import analyze as protocol_analyze, engines_for_symptoms
from app.protocols.registry import BY_NAME as PROTOCOL_ENGINES
from app.reasoning.inference import percent
from app.reasoning.report import ReasoningReport, analyze
from app.reasoning.specialists import AGENTS, PlannedCheck, Scope, checks_from_records, investigate as team_investigate
from app.security.permissions import HUMAN_ONLY, Permission, Principal
from app.security.secrets import redact

logger = logging.getLogger(__name__)

MAX_NOTES = 6
MAX_FACT_EVIDENCE = 12
FAULT_LABEL = {"wan_isp": "WAN / ISP circuit", "routing": "routing", "switching": "switching", "firewall": "firewall policy",
               "vlan_authentication": "VLAN / 802.1X authentication", "dhcp": "DHCP", "dns": "DNS",
               "network_device_failure": "network device failure", "interface_link": "interface / physical link",
               "shared_infrastructure": "shared infrastructure", "unknown": "unknown"}
PROTOCOL_SHORT = {"bgp": "BGP route", "ospf": "OSPF database", "stp": "spanning-tree", "arp": "ARP", "vlan": "trunk and VLAN", "nat": "NAT",
                  "ipsec": "VPN tunnel", "tcp": "TCP retransmission", "mtu": "MTU", "qos": "QoS", "ipv6": "IPv6", "wireless": "Wi-Fi",
                  "multicast": "multicast", "tls": "certificate and TLS", "threats": "threat correlation", "traffic": "suspicious-traffic",
                  "lateral": "lateral-movement", "all": "protocol and security"}
PROTOCOL_STATUS = {"confirmed_fault": "confirmed", "suspicious_indicator": "suspicious, not confirmed", "possible_explanation": "possible",
                   "insufficient_evidence": "not enough data"}
TOOL_LABEL = {"get_topology": "Site topology", "get_device_logs": "Device logs", "get_interface_stats": "Interface statistics",
              "get_routing_state": "Routing state", "get_firewall_logs": "Firewall logs", "get_dhcp_dns_status": "DHCP and DNS status",
              "check_network_reachability": "Path reachability", "analyze_packet_loss": "Packet loss analysis",
              "analyze_interface_errors": "Interface error analysis", "analyze_routing_adjacency": "Routing adjacency analysis",
              "check_device_availability": "Device availability", "analyze_network_dependencies": "Dependency analysis",
              "analyze_path_health": "Path health", "get_event_timeline": "Event timeline", "get_change_history": "Change history",
              "get_network_health": "Health scores", "get_config_drift": "Configuration drift",
              "analyze_traffic_flows": "Traffic flows", "trace_packet": "Packet journey", "forecast_capacity": "Capacity forecast",
              "analyze_protocol": "Protocol check", KNOWLEDGE_TOOL: "Knowledge search"}
EVIDENCE_KIND = {
    EvidenceType.OBSERVED_FINDING: ("an observed finding", "It was measured directly in the synthetic telemetry, not inferred."),
    EvidenceType.INFERRED_FINDING: ("an inferred finding", "The tool inferred it from other data, so it is weaker than a direct observation."),
    EvidenceType.OBSERVED_RESULT: ("an observed result", "It is the outcome of an evaluation the tool ran, such as a path or availability check."),
    EvidenceType.RECORD: ("a log record", "It is a raw log line, quoted as recorded."),
}
SCOPE_TEXT = {"everyone": "everyone", "some": "some users", "single": "a single user"}
SERVICE_TEXT = {"application": "internal applications", "internet": "internet access", "dns": "name resolution",
                "dhcp": "IP addressing (DHCP)", "authentication": "network sign-in (802.1X)"}
ASSUMED = {"scope": "number of affected users", "services": "affected services"}
ACRONYMS = re.compile(r"\b(erp|dns|dhcp|vpn|wan|lan|crm|sap|voip|wi-?fi|ip)\b", re.IGNORECASE)
TOOL_TOPIC = {"get_routing_state": "routing", "analyze_routing_adjacency": "adjacency", "analyze_packet_loss": "packet_loss",
              "analyze_interface_errors": "errors", "get_interface_stats": "interfaces", "get_device_logs": "logs",
              "check_device_availability": "availability", "get_dhcp_dns_status": "dhcp_dns", "get_topology": "topology",
              "analyze_network_dependencies": "dependencies", "check_network_reachability": "reachability",
              "get_firewall_logs": "firewall", "analyze_path_health": "path_health", "get_event_timeline": "timeline",
              "get_change_history": "changes", "get_network_health": "health_score", "get_config_drift": "drift",
              "analyze_traffic_flows": "traffic", "trace_packet": "journey", "forecast_capacity": "capacity"}
# A hypothesis question maps to the evidence codes that bear on it and to the check that would test it.
HYPOTHESIS_CODES = {
    "firewall": ("TRAFFIC_DENIED", "RULE_MODIFIED", "POLICY_"),
    "dns": ("DNS_",),
    "dhcp": ("DHCP_",),
    "vlan_authentication": ("DOT1X_", "PORT_UNAUTHORIZED", "RADIUS_"),
    "routing": ("ADJACENCY_", "NEIGHBOR_", "ROUTES_", "NEXT_HOP", "NO_ROUTE", "CONTROL_PLANE", "BGP_", "OSPF_"),
    "wan_isp": ("LINK_DOWN", "LINK_FLAP", "CARRIER_LOSS", "WAN_", "PACKET_LOSS", "PHYSICAL_LAYER", "PATH_SEGMENT"),
    "interface_link": ("INTERFACE", "HIGH_ERROR", "HIGH_DROP", "PHYSICAL_LAYER", "OPTICAL", "PATH_SEGMENT", "ERROR_COUNT"),
    "shared_infrastructure": ("TELEMETRY_GAP", "PEER_LINKS_DOWN", "DEVICE_FAILURE", "SHARED_"),
    "network_device_failure": ("TELEMETRY_GAP", "PEER_LINKS_DOWN", "DEVICE_FAILURE", "DEVICE_UNREACHABLE"),
    "switching": ("LINK_DOWN_ON_PATH", "STP_", "VLAN_"),
}
HYPOTHESIS_TOPIC = {"firewall": "firewall", "dns": "dhcp_dns", "dhcp": "dhcp_dns", "routing": "adjacency", "wan_isp": "packet_loss",
                    "interface_link": "errors", "shared_infrastructure": "dependencies", "network_device_failure": "availability",
                    "vlan_authentication": "logs", "switching": "logs"}
BEYOND_THE_SITE = {"firewall": "the data-centre firewall", "dns": "the DNS servers in the data centre",
                   "dhcp": "the DHCP server in the data centre", "vlan_authentication": "the RADIUS server in the data centre"}
DOWNSTREAM_CODES = ("DNS_UNREACHABLE_FROM_SITE", "DNS_TIMEOUTS", "DHCP_TRANSACTIONS_STOPPED")
SCOPE_REPORT = {"everyone": "All users at the affected site are impacted.", "some": "Only some users are impacted.",
                "single": "A single user is impacted."}
CAPABILITIES = [
    "Talk through the incident and explain the diagnosis and its evidence (E1, E2, ...) without re-running anything",
    "Run targeted read-only checks when asked: routing, BGP/OSPF adjacencies, interfaces, packet loss, interface errors, logs, "
    "reachability, firewall logs, DHCP/DNS, topology and dependencies",
    "Read network intelligence: health scores, configuration drift, traffic flows, hop-by-hop packet journeys and capacity "
    "forecasts (computed in code from simulated telemetry)",
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
# How deep a reply goes. Brief is the default; "why" questions get the reasons; "show the evidence" gets the technical list.
DEEPER = re.compile(r"\bwhy\b|how (?:do|did|can) you (?:know|tell)|what makes you|reasoning|justify|walk me through|in detail|more detail|"
                    r"elaborate|tell me more|based on what|explain (?:it |that |this )?(?:more|further|properly)", re.IGNORECASE)
SHOW_EVIDENCE = re.compile(r"\b(?:show|list|give|see)(?: me)? (?:the |all (?:the )?)?(?:evidence|raw)|\ball (?:the )?evidence\b|"
                           r"\bevidence list\b|\btechnical\b", re.IGNORECASE)
ATTACK_QUESTION = re.compile(r"\b(?:attack|breach|compromis\w*|intrusion|hack\w*|malicious)\b", re.IGNORECASE)
STEPS_WANTED = re.compile(r"\bsteps?\b|step[- ]by[- ]step|\bcommands?\b|walk me through|checklist|instructions|runbook|procedure|"
                          r"how (?:do|should|can|would) (?:i|we)|troubleshooting (?:guide|plan)", re.IGNORECASE)
TECHNICAL_ASK = re.compile(r"\b(?:technical|tech|raw)\b", re.IGNORECASE)
NEXT_CHECK = re.compile(r"\bwhat (?:should|do|can|would) (?:i|we) (?:check|look at|try|do)\b|\bwhat(?:'s| is) next\b|\bcheck next\b|"
                        r"\blook at next\b|\bnext check\b", re.IGNORECASE)
SHORTER = re.compile(r"\b(?:short(?:er|en)?|brief(?:er)?|concise|trim(?: it)?|cut it down|less wordy|tl;?dr)\b", re.IGNORECASE)
SECURITY_ENGINES = {"threats", "traffic", "lateral"}
# The protocol check that matches a technology users name, checked in report order. Vague wording follows the specialist rules:
# part of a population affected points at ARP, short freezes or a new desk at spanning tree.
NAMED_ENGINE = [(re.compile(p, re.IGNORECASE), engine) for p, engine in (
    (r"certificat|\btls\b|\bssl\b", "tls"), (r"\bvpn\b|tunnel|ipsec", "ipsec"), (r"wi-?fi|wireless|\bradar\b", "wireless"),
    (r"ipv6", "ipv6"), (r"multicast|\bvideo\b", "multicast"), (r"\bbgp\b", "bgp"), (r"\bospf\b", "ospf"),
    (r"\bloop\b|broadcast storm|spanning|freez|new desk", "stp"), (r"\bmtu\b|fragment", "mtu"), (r"\bqos\b|voice|choppy", "qos"),
    (r"\bnat\b|translation", "nat"), (r"\bhalf\b|some (?:users|desktops)|partial", "arp"))]
BROAD_TOPICS = {"logs", "availability", "routing", "adjacency", "interfaces"}
MAX_BROAD_CALLS = 4
OFFER_LOOKBACK = 4
NUMBER_WORD = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six"}
TOOL_PLAIN = {"check_network_reachability": "a reachability check", "get_firewall_logs": "the firewall logs",
              "analyze_packet_loss": "the packet-loss analysis", "analyze_interface_errors": "the interface error analysis",
              "get_interface_stats": "the interface counters", "get_routing_state": "the routing table",
              "analyze_routing_adjacency": "the routing neighbour check", "check_device_availability": "an availability check",
              "get_dhcp_dns_status": "the DHCP and DNS records", "get_device_logs": "the device logs",
              "analyze_path_health": "the path health check", "get_event_timeline": "the event timeline",
              "get_change_history": "the change history", "analyze_network_dependencies": "the dependency map",
              "get_topology": "the topology", "analyze_protocol": "a protocol check"}
ENGINE_FOCUS = {"bgp": "the BGP routes", "ospf": "the OSPF database", "stp": "spanning tree", "arp": "the ARP tables",
                "vlan": "the trunks and VLANs", "nat": "NAT", "ipsec": "the VPN tunnels", "tcp": "TCP retransmissions", "mtu": "MTU",
                "qos": "QoS", "ipv6": "IPv6", "wireless": "the Wi-Fi", "multicast": "multicast", "tls": "the certificates",
                "threats": "the security alerts", "traffic": "the traffic records", "lateral": "the login records"}


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


SERVICE_WORDS = {"application": r"erp|crm|sap|applications?|apps?|portal|intranet", "internet": r"internet|websites?|web",
                 "dns": r"dns", "dhcp": r"dhcp", "authentication": r"802\.1x|sign-?in|log-?in|radius", "email": r"e-?mail"}


def unaffected(service: str, text: str) -> bool:
    """True when the report says the service is fine ("ERP is fine", "ERP works"), so drafts don't list it as affected."""
    words = SERVICE_WORDS.get(service)
    return bool(words and re.search(rf"\b(?:{words})\b(?: (?:is|are|seems?|looks?|still))? (?:fine|ok|okay|works?|working|normal|"
                                    rf"unaffected|not affected)\b", text, re.IGNORECASE))


def bullet(item: EvidenceItem) -> str:
    """One evidence line. Inferred findings are labelled so a hypothesis never reads as a measured fact."""
    label = " (inferred, not measured)" if item.evidence_type == EvidenceType.INFERRED_FINDING else ""
    return f"- **{item.evidence_id}**{label}: {item.summary}"


def lower_first(text: str) -> str:
    """Lower-cases a sentence's first letter for use mid-sentence, leaving identifiers (SIN-RTR-01, E1, BGP) alone."""
    return text[:1].lower() + text[1:] if len(text) > 1 and text[0].isupper() and text[1].islower() else text


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
    details: str | None = None
    attachments: list[Attachment] = field(default_factory=list)
    result_by: Literal["ai_agent", "rule_based", "rule_based_fallback", "none"] = "none"
    level: Literal["brief", "detail", "technical"] = "brief"


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
        self.namer = Namer(self.index)

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
        if context.scenario_id and not scenario_exists(context.scenario_id):
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

    @staticmethod
    def adopt_evidence(state: ConversationState, investigation: Investigation) -> None:
        """Advances the conversation's evidence counter so the next investigation numbers its evidence after this one."""
        numbers = [int(item.evidence_id[1:]) for item in investigation.evidence if item.evidence_id[1:].isdigit()]
        state.evidence_seq = max([state.evidence_seq, *numbers])

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
        if action.kind == "multi_agent":
            return IntentResult(intent=Intent.MULTI_AGENT, confidence="high", source="quick_action", rerun=True)
        if action.kind == "protocol":
            calls = [PlannedCall(tool=c.tool, arguments=dict(c.arguments), reason="Approved by you") for c in action.calls[:6]
                     if c.tool == "analyze_protocol"]
            return IntentResult(intent=Intent.PROTOCOL_CHECK, confidence="high", source="quick_action", planned_calls=calls,
                                protocols=[c.arguments.get("protocol", "") for c in calls], rerun=True)
        if action.kind == "run_plan":
            calls = [PlannedCall(tool=c.tool, arguments=dict(c.arguments), reason="Approved by you") for c in action.calls[:4]]
            return IntentResult(intent=Intent.TARGETED_DIAGNOSTIC, confidence="high", source="quick_action", planned_calls=calls, rerun=True)
        call = PlannedCall(tool=action.tool or "", arguments=dict(action.arguments or {}), reason="Requested with a quick action")
        return IntentResult(intent=Intent.TARGETED_DIAGNOSTIC, confidence="high", source="quick_action", planned_calls=[call], rerun=True)

    def merge_context(self, turn: Turn) -> None:
        context = turn.state.context
        intent = turn.intent
        entities = intent.entities
        describes = intent.intent in (Intent.SYMPTOM_REPORT, Intent.CLARIFICATION, Intent.FULL_DIAGNOSIS) or (
            intent.intent == Intent.TARGETED_DIAGNOSTIC and bool(USER_REPORT.search(turn.user.content)))
        if entities.unaffected_site_ids and intent.intent not in (Intent.KNOWLEDGE, Intent.EVIDENCE_EXPLANATION):
            context.unaffected_site_ids = list(dict.fromkeys(context.unaffected_site_ids + entities.unaffected_site_ids))[:5]
            context.site_ids = [site for site in context.site_ids if site not in entities.unaffected_site_ids]
        if describes:
            context.unaffected_site_ids = [site for site in context.unaffected_site_ids if site not in entities.site_ids]
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
                                 Intent.CANCELLATION, Intent.HYPOTHESIS_CHECK, Intent.CLARIFICATION):
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
        outcome.facts.setdefault("detail_level", outcome.level)
        # Evidence-grounded validation applies to every reply, including the deterministic ones.
        template_issues = grounding_issues(outcome.template, outcome.facts, set(self.index.devices)) if outcome.facts.get("kind") != "error" else []
        if template_issues:
            logger.warning("Template reply failed validation: %s", "; ".join(template_issues))
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
        model_configured = self.composer.available
        result_by = outcome.result_by
        if investigation is not None and result_by == "none":
            result_by = ("rule_based_fallback" if investigation.fallback_used else "ai_agent" if investigation.mode == "agent"
                         else "rule_based")
        note = None
        if result_by == "rule_based_fallback":
            note = "The AI model didn't finish this diagnosis, so the rule-based engine produced the result."
        elif issues and model_configured:
            rejected = issues[0].removeprefix("Model reply rejected: ")
            note = ("I couldn't reach the AI service, so the rule-based composer wrote this reply instead."
                    if rejected == issues[0] else f"The AI model's reply was not used ({rejected}), so this is the rule-based version.")
        elif not model_configured:
            note = "No AI model is configured; replies and results are rule-based."
        generated = GeneratedBy(reply=composer, result=result_by, model_configured=model_configured, note=note)
        message = Message(message_id=message_id, turn_id=turn.handle.turn_id, role="assistant", content=text, created_at=now(),
                          intent=intent.intent, status=outcome.status, composer=composer,
                          investigation_id=investigation.investigation_id if investigation else None,
                          evidence_refs=[self.plain_ref(ref) for ref in outcome.evidence[:20]], suggested_actions=outcome.actions[:6], clarification=outcome.clarification,
                          human_confirmations=outcome.confirmations, details=outcome.details, attachments=outcome.attachments[:4],
                          generated_by=generated)
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
            fallback_used=investigation.fallback_used if investigation else False, composer_issues=(issues + template_issues)[:5],
        )
        result = TurnResult(
            conversation_id=state.conversation_id, turn_id=turn.handle.turn_id,
            intent=IntentView(name=intent.intent, confidence=intent.confidence, source=intent.source, entities=intent.entities,
                              topics=intent.topics),
            response=text, user_message=turn.user, assistant_message=message, clarification=outcome.clarification,
            investigation_id=investigation.investigation_id if investigation else None, execution=execution,
            evidence_references=message.evidence_refs, suggested_actions=message.suggested_actions,
            human_confirmations=message.human_confirmations, context=state.context.model_copy(deep=True),
            details=message.details, attachments=message.attachments, generated_by=generated,
        )
        if outcome.status == "completed":
            state.context.last_intent = intent.intent.value
        self.store.save(state)
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
            self.adopt_evidence(turn.state, investigation)
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
            "investigation_ids": list(turn.state.investigations)[-10:],
            "confirmed_by_person": bool(turn.incident and turn.incident.classification.confirmed_fault_domain),
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

    # ---------- plain-language helpers ----------

    def plain_ref(self, ref: EvidenceReference) -> EvidenceReference:
        """Adds a plain-words version of the summary for tooltips. The audit summary itself is never changed."""
        if ref.plain:
            return ref
        try:
            item = SimpleNamespace(code=ref.code, summary=ref.summary, device_id=ref.device_id, evidence_id=ref.evidence_id,
                                   evidence_type=EvidenceType(ref.evidence_type))
            return ref.model_copy(update={"plain": sentence(self.namer.clause(item))})
        except (ValueError, KeyError):
            return ref

    def offices(self, turn: Turn) -> list[str]:
        return list(turn.incident.site_ids if turn.incident else turn.state.context.site_ids)

    def is_confirmed(self, turn: Turn, diagnosis: Diagnosis | None) -> bool:
        confirmed = turn.incident.classification.confirmed_fault_domain if turn.incident else None
        return bool(diagnosis is not None and confirmed is not None and confirmed == diagnosis.fault.fault_domain)

    @staticmethod
    def open_case(diagnosis: Diagnosis | None) -> bool:
        return diagnosis is None or diagnosis.fault.fault_domain.value == "unknown" \
            or diagnosis.confidence.level.value == "insufficient_evidence"

    def reported_problem(self, turn: Turn) -> str:
        incident = turn.incident
        if incident is not None:
            return problem_of(incident.title, incident.symptoms, incident.description)
        context = turn.state.context
        return problem_of(" ".join(context.notes[-2:]), context.symptoms)

    def security_mentions(self, turn: Turn) -> list[str]:
        incident = turn.incident
        if incident is not None:
            return self.namer.security_mentions(incident.title, incident.description, incident.symptoms)
        context = turn.state.context
        return self.namer.security_mentions(" ".join(context.notes[-3:]), "", context.symptoms)

    @staticmethod
    def security_check(turn: Turn) -> Investigation | None:
        """The latest protocol check in this conversation that looked at threats, suspicious traffic or lateral movement."""
        return next((i for i in reversed(turn.state.investigations.values()) if i.kind == "protocol_check" and i.protocol
                     and SECURITY_ENGINES & {e.get("engine") for e in i.protocol.get("engines", [])}), None)

    def security_line(self, turn: Turn) -> str | None:
        """Security activity in the report is never dropped from an explanation. Until a security check runs it stays open."""
        mentions = self.security_mentions(turn)
        if not mentions:
            return None
        checked = self.security_check(turn)
        if checked is not None:
            return f"On the security side, I ran the checks earlier. {sentence(checked.protocol['headline'])}"
        verb, pronoun = ("aren't", "they're") if len(mentions) > 1 else ("isn't", "it's")
        return (f"{capital(join(mentions))} in the report {verb} covered by any evidence yet, so {pronoun} neither confirmed nor "
                "ruled out.")

    def with_security(self, turn: Turn, facts: dict[str, Any], parts: list[str]) -> list[str]:
        """Appends the security line and records it, so a model rewrite that drops it is rejected."""
        security = self.security_line(turn)
        if security:
            parts.append(security)
            facts["warnings"] = [security]
        return parts

    def short_state(self, turn: Turn, diagnosis: Diagnosis | None) -> str:
        if diagnosis is None:
            return "Nobody has run a diagnosis yet."
        if self.open_case(diagnosis):
            return "No cause found yet."
        what = FAULT_PLAIN.get(diagnosis.fault.fault_domain.value, "a fault")
        if self.is_confirmed(turn, diagnosis):
            return f"The cause is confirmed as {what}."
        return f"My best lead is {what}, not confirmed yet."

    def diagnosis_brief(self, turn: Turn, diagnosis: Diagnosis, items: list[EvidenceItem],
                        short: bool = False) -> tuple[str, list[EvidenceItem]]:
        """Where the diagnosis stands in two or three sentences: the verdict, the main reason, and what is still open."""
        namer, fault, offices = self.namer, diagnosis.fault, self.offices(turn)
        by_id = {item.evidence_id: item for item in items}
        supporting = [by_id[e] for e in fault.supporting_evidence_ids if e in by_id]
        verdict = namer.verdict(diagnosis, self.is_confirmed(turn, diagnosis))
        if supporting:
            clauses = [text for text, _ in namer.grouped(supporting, offices=offices)][:2]
            parts = [verdict, f"The main sign is that {clauses[0]}" + (f", and {clauses[1]}" if len(clauses) > 1 else "") + "."]
            if fault.contradictory_evidence_ids:
                parts.append("One piece of evidence doesn't fit, so treat it as provisional.")
            return " ".join(parts), supporting[:4]
        what = self.reported_problem(turn)
        healthy = [item for item in items if item.code in HEALTHY]
        odd = [item for item in items if item.code not in HEALTHY]
        fine = [self.untimed(text) for text, _ in namer.grouped(healthy, offices=offices)]
        strange = [self.untimed(text) for text, _ in namer.grouped(odd, offices=offices)]
        if short or not (fine or strange):
            parts = [verdict, f"Nothing in the evidence so far explains {what}."]
        else:
            parts = [f"{verdict[:-1]}, though {fine[0]}." if fine and verdict.startswith("I haven't") else verdict]
            if fine and not verdict.startswith("I haven't"):
                parts.append(sentence(fine[0]))
            if len(strange) == 1:
                parts.append(f"The only odd thing is that {strange[0]}, and that isn't enough to explain {what}.")
            elif strange:
                parts.append(f"I did find that {strange[0]}, but nothing I've collected explains {what}.")
            else:
                parts.append(f"Nothing I've collected explains {what}.")
        return " ".join(parts), (healthy + odd)[:6]

    @staticmethod
    def untimed(text: str) -> str:
        return re.sub(r" (?:at|between) \d{2}:\d{2}(?: and \d{2}:\d{2})? UTC$", "", text)

    def diagnosis_reasons(self, turn: Turn, diagnosis: Diagnosis, items: list[EvidenceItem]) -> tuple[str, list[EvidenceItem]]:
        """The "why" answer: each piece of evidence that matters, in plain words, with its id and what it means."""
        namer, fault, offices = self.namer, diagnosis.fault, self.offices(turn)
        by_id = {item.evidence_id: item for item in items}
        supporting = [by_id[e] for e in fault.supporting_evidence_ids if e in by_id]
        if supporting:
            head = namer.verdict(diagnosis, self.is_confirmed(turn, diagnosis), with_ids=True)
            shown = namer.grouped(supporting, True, offices)[:2]
            against = [by_id[e] for e in fault.contradictory_evidence_ids if e in by_id]
            unfit = namer.grouped(against, True, offices)[:1]
            lines = [head, "Here's what points to it:"] + [f"- {capital(text)} ({ids_text(ids)})." for text, ids in shown]
            lines += [f"- {capital(text)} ({ids_text(ids)}). This one doesn't fit, which is why confidence isn't higher."
                      for text, ids in unfit]
            cited_ids = [e for _, ids in shown + unfit for e in ids]
            inferred = [e for e in cited_ids if by_id[e].evidence_type == EvidenceType.INFERRED_FINDING]
            if inferred:
                lines.append(f"{ids_text(inferred)} {'is' if len(inferred) == 1 else 'are'} inferred from other data rather than "
                             "measured directly.")
            return first_mention("\n".join(lines)), [by_id[e] for e in cited_ids]
        chosen = items[:8]
        lines = ["I haven't found the cause yet. Here's what I have:"]
        lines += [f"- {capital(text)} ({ids_text(ids)}). {namer.meaning(by_id[ids[0]], diagnosis)}"
                  for text, ids in namer.grouped(chosen, True, offices)[:5]]
        lines.append(f"None of it explains {self.reported_problem(turn)}.")
        return first_mention("\n".join(lines)), chosen

    def evidence_listing(self, turn: Turn, diagnosis: Diagnosis, items: list[EvidenceItem]) -> str:
        fault = diagnosis.fault
        state = "confirmed" if self.is_confirmed(turn, diagnosis) else "not confirmed"
        head = (f"**{fault.root_cause}** ({FAULT_LABEL.get(fault.fault_domain.value)}, "
                f"{diagnosis.confidence.level.value.replace('_', ' ')} confidence, {state}).")
        listed = "\n".join(f"{bullet(item)} ({TOOL_LABEL.get(item.tool, item.tool)}, {item.call_id})" for item in items[:12])
        more = f"\n{len(items) - 12} more items are in the evidence tab." if len(items) > 12 else ""
        return f"{head}\n\nEvidence:\n{listed}{more}"

    def findings_brief(self, turn: Turn, items: list[EvidenceItem], level: str) -> tuple[str, list[EvidenceItem]]:
        groups = self.namer.grouped(items[:8], with_ids=level != "brief", offices=self.offices(turn))
        if level == "brief":
            more = f" I also found that {groups[1][0]}." if len(groups) > 1 else ""
            return f"There's no diagnosis yet, only targeted checks. {sentence(groups[0][0])}{more}", items[:5]
        lines = ["There's no diagnosis yet. Here's what the targeted checks found:"]
        lines += [f"- {capital(text)} ({ids_text(ids)})." for text, ids in groups[:6]]
        return "\n".join(lines), items[:8]

    def diagnosis_details(self, turn: Turn, diagnosis: Diagnosis | None, items: list[EvidenceItem], source: str,
                          investigation_id: str | None) -> str:
        """The technical version behind "Show details": hypothesis, raw evidence lines, reasoning and confidence."""
        if diagnosis is None:
            return f"Here's the evidence from {source}:\n" + "\n".join(bullet(item) for item in items[:8])
        fault = diagnosis.fault
        by_id = {item.evidence_id: item for item in items}
        chosen = [by_id[e] for e in fault.supporting_evidence_ids if e in by_id][:5] or items[:5]
        reasoning = self.reasoning_for(turn, investigation_id)
        extra = ""
        if reasoning is not None:
            why = "\n".join(f"- {line}" for line in reasoning.explanation.why[:3])
            alternatives = "\n".join(f"- {line}" for line in reasoning.explanation.alternatives)
            extra = (f"\n\nHow it fits together:\n{why}" if why else "") + (
                f"\n\nWhy not the alternatives:\n{alternatives}" if alternatives else "") + f"\n\n{reasoning.explanation.uncertainty}"
        return (f"The hypothesis is **{fault.root_cause}** ({FAULT_LABEL.get(fault.fault_domain.value)}, "
                f"{diagnosis.confidence.level.value.replace('_', ' ')} confidence). {fault.reasoning}\n\n"
                + "\n".join(bullet(item) for item in chosen) + extra
                + f"\n\n{diagnosis.confidence.explanation} This comes from {source}; I didn't re-run anything.")

    def explain_one(self, item: EvidenceItem, diagnosis: Diagnosis | None) -> str:
        namer = self.namer
        if item.evidence_type == EvidenceType.RECORD:
            when = f" at {item.timestamp:%H:%M} UTC" if item.timestamp else ""
            message = re.sub(r"^\[\w+\]\s*", "", item.summary).rstrip(".")
            return (f"**{item.evidence_id}** is a log line from {namer.device(item.device_id)}{when}. It reads \"{message}\". "
                    f"{namer.meaning(item, diagnosis)}")
        tool = TOOL_PLAIN.get(item.tool, f"the {TOOL_LABEL.get(item.tool, item.tool).lower()}")
        where = ""
        if item.device_id:
            where = (f" run from {namer.device(item.device_id)}" if item.tool == "check_network_reachability"
                     else f" on {namer.device(item.device_id)}")
        supporting = diagnosis.fault.supporting_evidence_ids if diagnosis else []
        inferred = (" It's inferred from other data, not measured directly."
                    if item.evidence_type == EvidenceType.INFERRED_FINDING and item.evidence_id not in supporting else "")
        return (f"**{item.evidence_id}** comes from {tool}{where}. It shows that {namer.clause(item)}.{inferred} "
                f"{namer.meaning(item, diagnosis)}")

    def confirmed_answer(self, turn: Turn, diagnosis: Diagnosis | None, facts: dict[str, Any]) -> tuple[str, list[SuggestedAction]]:
        classification = turn.incident.classification if turn.incident else None
        if classification is not None and classification.confirmed_fault_domain is not None:
            who = classification.confirmed_by.actor_id if classification.confirmed_by else "Someone"
            return f"Yes. {who} confirmed the fault domain as {FAULT_LABEL.get(classification.confirmed_fault_domain.value)}.", []
        if diagnosis is None:
            return "No. Nobody has run a diagnosis yet, so there's nothing to confirm.", self.propose_diagnosis(turn)
        if self.open_case(diagnosis):
            parts = self.with_security(turn, facts, ["No. The diagnosis hasn't found a cause, so there's nothing to confirm yet."])
            return " ".join(parts), [reply("What should I check next?")]
        level = diagnosis.confidence.level.value.replace("_", " ")
        return (f"No. The diagnosis says {self.namer.cause(diagnosis.fault.root_cause)}, at {level} confidence, but nobody has "
                "confirmed it. Someone with the right role can do that with Review and confirm after checking it."), \
            [reply("Why do you think that?")]

    def attack_answer(self, turn: Turn) -> str:
        checked = self.security_check(turn)
        if checked is not None:
            return f"Not as far as I can tell. {sentence(checked.protocol['headline'])}"
        mentions = self.security_mentions(turn)
        if mentions:
            verb, pronoun = ("aren't", "they're") if len(mentions) > 1 else ("isn't", "it's")
            return (f"No, nothing confirms an attack. {capital(join(mentions))} in the report {verb} covered by any evidence yet, "
                    f"so {pronoun} neither confirmed nor ruled out.")
        return "No, nothing I've collected points to an attack."

    def suggested_engines(self, turn: Turn) -> list[str]:
        """Protocol checks that fit what users report, when the core diagnosis found nothing. The primary symptom picks one;
        security activity in the report adds the threat check. Checks already run here are skipped."""
        incident, context = turn.incident, turn.state.context
        primary = (f"{incident.title.split(';')[0]} {(incident.symptoms or [''])[0]}" if incident
                   else " ".join(context.notes[-1:] + context.symptoms[:1]))
        report = [incident.title, *incident.symptoms] if incident else context.notes[-2:] + context.symptoms
        named = next((engine for text in report for pattern, engine in NAMED_ENGINE if pattern.search(text)), None)
        engines = [named] if named else [e for e in engines_for_symptoms(primary) if e in PROTOCOL_ENGINES
                                         and e not in SECURITY_ENGINES][:1]
        if self.security_mentions(turn):
            engines.append("threats")
        done = {e.get("engine") for i in turn.state.investigations.values() if i.kind == "protocol_check" and i.protocol
                for e in i.protocol.get("engines", [])}
        return [e for e in dict.fromkeys(engines) if e not in done][:3]

    def focus_devices(self, turn: Turn) -> list[str]:
        """Devices that matter most for this incident: the fault's devices, devices with odd evidence, then each site's router."""
        diagnosis, _, _ = self.current_diagnosis(turn)
        devices: list[str | None] = list(diagnosis.fault.device_ids) if diagnosis else []
        if diagnosis is not None:
            devices += [item.device_id for item in diagnosis.evidence if item.code not in HEALTHY]
        devices += [self.index.site_device(site, DeviceRole.WAN_EDGE) for site in self.offices(turn)]
        if diagnosis is not None:
            devices += [item.device_id for item in diagnosis.evidence]
        return [d for d in dict.fromkeys(devices) if d and d in self.index.devices]

    @staticmethod
    def pending_from(action: SuggestedAction) -> PendingAction | None:
        params = action.params or {}
        calls = [PlannedCall(tool=c["tool"], arguments=dict(c.get("arguments") or {}), reason="Offered earlier")
                 for c in params.get("calls", []) if isinstance(c, dict) and c.get("tool")]
        if action.kind == "run_plan" and calls:
            return PendingAction(kind="plan", calls=calls[:4], proposed_at=now())
        if action.kind == "protocol" and calls:
            return PendingAction(kind="protocol", calls=calls[:6], proposed_at=now())
        if action.kind == "targeted_check" and params.get("tool"):
            return PendingAction(kind="targeted_check", proposed_at=now(), calls=[
                PlannedCall(tool=params["tool"], arguments=dict(params.get("arguments") or {}), reason="Offered earlier")])
        if action.kind in ("full_diagnosis", "multi_agent"):
            return PendingAction(kind=action.kind, proposed_at=now())
        return None

    def offer_text(self, pending: PendingAction) -> str:
        if pending.kind == "full_diagnosis":
            return "the full read-only diagnosis I offered earlier"
        if pending.kind == "multi_agent":
            return "the specialist review I offered earlier"
        if pending.kind == "protocol":
            engines = [c.arguments.get("protocol", "") for c in pending.calls]
            return f"the read-only check{'s' if len(engines) > 1 else ''} of {join(ENGINE_FOCUS.get(e, e) for e in engines)} I offered earlier"
        labels = list(dict.fromkeys(TOOL_LABEL.get(c.tool, c.tool).lower() for c in pending.calls))
        devices = list(dict.fromkeys(c.arguments.get("device_id") for c in pending.calls if c.arguments.get("device_id")))
        where = f" on {self.namer.device(devices[0])}" if len(devices) == 1 else f" on {len(devices)} devices" if devices else ""
        return f"the read-only check{'s' if len(pending.calls) > 1 else ''} I offered earlier, {join(labels)}{where}"

    def reoffer(self, turn: Turn) -> Outcome:
        """"Go ahead" with nothing waiting. A recent offer is asked about again by name; nothing runs on this turn, and an
        offer the user declined or cancelled is never brought back."""
        offer = None
        seen = 0
        for message in reversed(turn.state.messages[:-1]):
            if message.role != "assistant":
                continue
            seen += 1
            if seen > OFFER_LOOKBACK or message.intent in (Intent.DECLINE, Intent.CANCELLATION):
                break
            offer = next((a for a in message.suggested_actions if a.executes_tools and a.allowed), None)
            if offer is not None:
                break
        pending = self.pending_from(offer) if offer is not None and self.can_diagnose(turn) else None
        if pending is None:
            return Outcome(template="There's nothing waiting for a go-ahead right now. What would you like me to do?",
                           facts=self.facts(turn, "nothing_pending"), use_model=False)
        turn.state.context.pending_action = pending
        return Outcome(template=f"Do you mean {self.offer_text(pending)}? We've talked about other things since, so I'd rather check "
                                "than run something you didn't mean.",
                       facts=self.facts(turn, "offer_repeated", proposal=offer.label), use_model=False,
                       actions=[offer, reply("No thanks")])

    def propose_broad(self, turn: Turn) -> Outcome:
        """"Check every log": never run as asked. The devices that matter most are offered as a bounded, approved plan."""
        topic = (turn.intent.topics or ["logs"])[0]
        tool = TOPIC_TOOL.get(topic)
        devices = self.focus_devices(turn)[:MAX_BROAD_CALLS] if topic in BROAD_TOPICS else []
        if tool is None or not devices:
            return Outcome(template="Checking everything at once would be a lot, and most of it wouldn't relate to this incident. "
                                    "Which site or device should I start with?", facts=self.facts(turn, "broad_request"), use_model=False)
        calls = [PlannedCall(tool=tool, arguments={"device_id": d}, reason=f"Read the {TOPIC_LABEL[topic]} of {d}") for d in devices]
        turn.state.context.pending_action = PendingAction(kind="plan", calls=calls, proposed_at=now())
        count = NUMBER_WORD.get(len(devices), str(len(devices)))
        what = "every log on every device" if topic == "logs" else f"the {TOPIC_LABEL[topic]} of every device"
        label = f"Read {TOPIC_LABEL[topic]} on {len(devices)} device{'s' if len(devices) != 1 else ''}"
        template = (f"Reading {what} would be a lot, and most of it has nothing to do with this incident. I can read the "
                    f"{TOPIC_LABEL[topic]} on the {count} devices that matter most here, {join(self.namer.device(d) for d in devices)}. "
                    f"That's {count} read-only call{'s' if len(devices) != 1 else ''}. Go ahead?")
        return Outcome(template=template, facts=self.facts(turn, "broad_request", proposal=label), use_model=False,
                       actions=[act("run_plan", label, {"calls": [{"tool": c.tool, "arguments": c.arguments} for c in calls]}, tools=True),
                                reply("No thanks")])

    def grounds(self, turn: Turn) -> assist.Grounds:
        """What troubleshooting may rest on: the diagnosis and its state, its evidence, targeted checks run here, and the report."""
        incident, context = turn.incident, turn.state.context
        diagnosis, _, _ = self.current_diagnosis(turn)
        evidence = list(diagnosis.evidence) if diagnosis else []
        seen = {item.evidence_id for item in evidence}
        for investigation in turn.state.investigations.values():
            evidence += [item for item in investigation.evidence if item.evidence_id not in seen]
            seen |= {item.evidence_id for item in investigation.evidence}
        report = (assist.clauses(incident.title, incident.description, *incident.symptoms) if incident
                  else assist.clauses(*context.notes[-4:], *context.symptoms))
        sites = list(incident.site_ids if incident else context.site_ids)
        base = dict(report=report, sites=sites, evidence=evidence)
        confirmed = incident.classification.confirmed_fault_domain if incident else None
        if confirmed is not None:
            devices = list(diagnosis.fault.device_ids) if diagnosis and diagnosis.fault.fault_domain == confirmed else []
            return assist.Grounds(status="confirmed", domain=confirmed, devices=devices, **base)
        if self.open_case(diagnosis):
            return assist.Grounds(status="unknown", **base)
        by_id = {item.evidence_id: item for item in diagnosis.evidence}
        against = [by_id[e] for e in diagnosis.fault.contradictory_evidence_ids if e in by_id]
        return assist.Grounds(status="conflicting" if against else "suspected", domain=diagnosis.fault.fault_domain,
                              contradicting=against, devices=list(diagnosis.fault.device_ids), **base)

    def grounded(self, turn: Turn, kind: str, grounds: assist.Grounds, plan: assist.Plan | None = None,
                 **extra: Any) -> tuple[dict[str, Any], list[EvidenceReference]]:
        """Facts and evidence chips for a troubleshooting reply: every id the reply may cite is in the facts."""
        facts = self.facts(turn, kind, **extra)
        facts["evidence_ids"] = sorted(set(facts["evidence_ids"]) | {item.evidence_id for item in grounds.evidence})
        cited = set(plan.evidence_ids + [e for ids in plan.ruled_out.values() for e in ids]) if plan else set()
        _, investigation_id, diagnosis_id = self.current_diagnosis(turn)
        refs = [reference(item, investigation_id, diagnosis_id) for item in grounds.evidence if item.evidence_id in cited]
        return facts, refs[:8]

    def guide_lead(self, grounds: assist.Grounds, plan: assist.Plan, count: int) -> str:
        """One or two sentences saying what the steps rest on: confirmed, likely, conflicting, or only the evidence and report."""
        label = FAULT_LABEL.get(grounds.domain.value, grounds.domain.value) if grounds.domain else None
        steps = f"{count} read-only steps" if count != 1 else "read-only step"
        covered = assist.COVERS.get(grounds.domain, {grounds.domain}) if grounds.domain else set()
        others = " The later ones follow what users report and the other evidence." \
            if any(c.domain not in covered for c in plan.commands) else ""
        if grounds.status == "confirmed":
            lead = f"The cause is confirmed as {label}. {'These' if count != 1 else 'This'} {steps} check{'' if count != 1 else 's'} it.{others}"
        elif grounds.status == "suspected":
            lead = (f"{'These' if count != 1 else 'This'} {steps} follow{'' if count != 1 else 's'} the likely {label} fault, "
                    f"which isn't confirmed yet.{others}")
        elif grounds.status == "conflicting":
            item = grounds.contradicting[0]
            lead = (f"The evidence conflicts. It points to {label}, but {self.untimed(self.namer.clause(item))} "
                    f"({item.evidence_id}) doesn't fit, so these {steps} check both.")
        else:
            lead = (f"Nothing points at a cause yet, so {'these' if count != 1 else 'this'} {steps} "
                    f"follow{'' if count != 1 else 's'} from {self.basis(grounds, plan)}.")
        notes = []
        if grounds.status == "unknown" and plan.ruled_out:
            ids = [e for site_ids in plan.ruled_out.values() for e in site_ids]
            notes.append(f"I left out routing checks for {self.namer.sites(plan.ruled_out)} because the path from there works "
                         f"({ids_text(ids)}).")
        for item in plan.telemetry_gaps[:1]:
            notes.append(f"Telemetry from {self.namer.device(item.device_id)} is missing ({item.evidence_id}), so the data can't "
                         "show what it's doing. These checks look at it directly.")
        return " ".join([lead] + notes)

    def basis(self, grounds: assist.Grounds, plan: assist.Plan) -> str:
        """What unknown-cause checks rest on: the evidence that looks wrong, and what users report."""
        by_id = {item.evidence_id: item for item in grounds.evidence}
        basis = []
        first = by_id.get(plan.evidence_ids[0]) if "evidence" in plan.reasons and plan.evidence_ids else None
        if first is not None:
            basis.append(f"the evidence, mainly that {self.untimed(self.namer.clause(first))} ({first.evidence_id})")
        if "report" in plan.reasons:
            basis.append("what users report")
        return join(basis) or "the evidence"

    def first_step(self, turn: Turn, grounds: assist.Grounds, plan: assist.Plan, more: list[SuggestedAction]) -> Outcome:
        first = plan.commands[0]
        facts, refs = self.grounded(turn, "next_check", grounds, plan)
        return Outcome(template=f"Nothing points at a cause yet. Going by {self.basis(grounds, plan)}, I'd start with "
                                f"`{first.command}` on {self.namer.device(first.device_id)}. It checks "
                                f"{plain_lower(first.purpose.rstrip('.'))}. Want the full step-by-step list?",
                       facts=facts, evidence=refs, actions=more, use_model=False)

    def more_evidence(self, turn: Turn, grounds: assist.Grounds) -> Outcome:
        """No step is justified: say so, and offer the read-only collection that would help. Nothing runs here."""
        diagnosis, _, _ = self.current_diagnosis(turn)
        gaps = [item for item in grounds.evidence if item.code in assist.TELEMETRY_CODES]
        why = ("the telemetry is incomplete" if gaps else
               "the cause is unknown and nothing in the evidence or the report points at a particular device or service")
        template = f"I can't point to specific commands yet, because {why}."
        actions: list[SuggestedAction] = []
        facts_extra: dict[str, Any] = {}
        if self.can_diagnose(turn) and diagnosis is None:
            actions = self.propose_diagnosis(turn)
            template += " Rather than guess, I'd run a full read-only diagnosis to collect the evidence first. Want me to run it?"
            facts_extra["proposal"] = "Run a full read-only diagnosis"
        elif self.can_diagnose(turn) and (engines := self.suggested_engines(turn)):
            calls = self.protocol_calls(turn, engines)
            turn.state.context.pending_action = PendingAction(kind="protocol", calls=calls, proposed_at=now())
            focus = join(ENGINE_FOCUS.get(e, f"the {PROTOCOL_SHORT.get(e, e)} data") for e in engines)
            label = f"Check {focus}"
            template += f" Rather than guess, I'd look at {focus} first. Want me to run that read-only check?"
            actions = [self.protocol_action(label, calls), reply("No thanks")]
            facts_extra["proposal"] = label
        else:
            template += " Tell me what users see, or name a device, and I'll suggest checks for it."
        facts, _ = self.grounded(turn, "troubleshooting_needs_evidence", grounds, **facts_extra)
        return Outcome(template=template, facts=facts, actions=actions, use_model=False)

    async def next_check(self, turn: Turn) -> Outcome:
        """What to check next, in a sentence or two. The check is offered, never run, until the user says so."""
        context = turn.state.context
        diagnosis, investigation_id, _ = self.current_diagnosis(turn)
        more = [reply("Give me step-by-step troubleshooting")]
        if diagnosis is None:
            proposal = self.propose_diagnosis(turn)
            if proposal:
                return Outcome(template="Nobody has run a diagnosis yet, so I'd start there. It's read-only. Want me to run it?",
                               facts=self.facts(turn, "next_check", proposal="Run a full read-only diagnosis"), actions=proposal,
                               use_model=False)
        grounds = self.grounds(turn)
        site, device = self.guide_target(turn)
        plan = assist.plan_checks(grounds, site, device)
        from_evidence = bool(plan.commands) and "evidence" in plan.reasons and bool(plan.evidence_ids)
        if self.open_case(diagnosis) and from_evidence:
            return self.first_step(turn, grounds, plan, more)
        if self.open_case(diagnosis) and self.can_diagnose(turn):
            engines = self.suggested_engines(turn)
            if engines:
                calls = self.protocol_calls(turn, engines)
                context.pending_action = PendingAction(kind="protocol", calls=calls, proposed_at=now())
                focus = join(ENGINE_FOCUS.get(e, f"the {PROTOCOL_SHORT.get(e, e)} data") for e in engines)
                both = "that check" if len(engines) == 1 else "both checks" if len(engines) == 2 else f"those {len(engines)} checks"
                label = f"Check {focus}"
                return Outcome(template=f"Nothing so far points at a device, so I'd look at {focus} next. I can run {both} now. "
                                        f"{'They only read' if len(engines) > 1 else 'It only reads'} telemetry that's already been "
                                        "collected. Go ahead?",
                               facts=self.facts(turn, "next_check", proposal=label), use_model=False,
                               actions=[self.protocol_action(label, calls), reply("No thanks")] + more)
        if self.open_case(diagnosis):
            return self.first_step(turn, grounds, plan, more) if plan.commands else self.more_evidence(turn, grounds)
        reasoning = self.reasoning_for(turn, investigation_id)
        domain = grounds.domain.value if grounds.domain else None
        relevant = [step for step in reasoning.plan if domain in step.tests] if reasoning is not None else []
        offer = None
        if relevant and self.can_diagnose(turn):
            step = relevant[0]
            calls = [PlannedCall(tool=step.tool, arguments=step.arguments, reason=step.purpose)]
            context.plan = calls
            context.pending_action = PendingAction(kind="plan", calls=calls, proposed_at=now())
            offer = act("run_plan", "Run 1 more check", {"calls": [{"tool": step.tool, "arguments": step.arguments}]}, tools=True)
        elif plan.commands:
            first = plan.commands[0]
            facts, refs = self.grounded(turn, "next_check", grounds, plan)
            label = FAULT_LABEL.get(domain, domain) if domain else "the evidence"
            return Outcome(template=f"Going by the likely {label} fault, which isn't confirmed yet, I'd start with `{first.command}` on "
                                    f"{self.namer.device(first.device_id)}. It checks {plain_lower(first.purpose.rstrip('.'))}. "
                                    "Want the full step-by-step list?", facts=facts, evidence=refs, actions=more, use_model=False)
        if offer is not None:
            question = relevant[0].reason.strip().rstrip(".?")
            return Outcome(template=f"I'd check this next. {capital(question)}? Want me to run it? It's read-only.",
                           facts=self.facts(turn, "next_check", proposal=offer.label), actions=[offer, reply("Not yet")] + more,
                           use_model=False)
        checks = diagnosis.next_checks if diagnosis else []
        if checks:
            check = checks[0]
            return Outcome(template=f"I'd run `{check.command}` on {self.namer.device(check.device_id)} next, to "
                                    f"{plain_lower(check.purpose.rstrip('.'))}. Want the full step-by-step list?",
                           facts=self.facts(turn, "next_check"), actions=more, use_model=False)
        return Outcome(template="There's nothing obvious left to check. I can write up step-by-step troubleshooting or draft a customer "
                                "update.", facts=self.facts(turn, "nothing_next"), actions=more + [reply("Draft a customer update")],
                       use_model=False)

    # ---------- intent handlers (no tools) ----------

    async def on_greeting(self, turn: Turn) -> Outcome:
        incident = turn.incident
        actions = []
        if incident is not None:
            diagnosis, _, _ = self.current_diagnosis(turn)
            closed = f" It's {incident.status.value}." if incident.status.value in ("resolved", "closed") else ""
            template = (f"Hi. I'm on {incident.incident_id}, about {self.reported_problem(turn)}.{closed} "
                        f"{self.short_state(turn, diagnosis)} What do you need?")
            if diagnosis is not None:
                actions.append(reply("Explain the current diagnosis"))
        else:
            template = "Hi. What are users seeing? I can check a device or site, or diagnose the problem."
        actions.append(reply("What can you do?"))
        return Outcome(template=template, facts=self.facts(turn, "greeting"), actions=actions, use_model=False)

    async def on_general(self, turn: Turn) -> Outcome:
        text = turn.user.content
        if AFFIRM.match(text.strip()) and len(text.split()) <= 4 and not human_action_in(text):
            # "Go ahead" with nothing waiting: ask what it refers to. Nothing runs on this turn.
            return self.reoffer(turn)
        settled = True
        if re.match(r"^(?:thanks?|thank you|thx|ty|cheers)", text, re.IGNORECASE):
            template = "You're welcome."
        elif re.match(r"^(?:bye|goodbye|see you|that's all|that is all)", text, re.IGNORECASE):
            template = "Okay. This conversation stays here if you need it again."
        elif turn.intent.confidence == "high":
            template = "Got it. Tell me what you want to look at next."
        else:
            settled = False
            template = ("I didn't follow that. You can ask what's wrong, why I think so or what to check next, or name a device to "
                        "check, like \"check SIN-RTR-01 routing\".")
        return Outcome(template=template, facts=self.facts(turn, "general_conversation", assistant_capabilities=CAPABILITIES),
                       use_model=not settled)

    async def on_capabilities(self, turn: Turn) -> Outcome:
        lines = "\n".join(f"- {line}." for line in CAPABILITIES)
        role = ("" if can(turn.principal, Permission.RUN_DIAGNOSTICS)
                else " Your role can read the conversation and evidence but can't run checks.")
        template = ("I can explain the diagnosis and its evidence, run read-only checks you ask for, diagnose the incident, give "
                    "step-by-step troubleshooting with exact commands, and draft customer emails and updates. I never change devices "
                    "or incidents." + role)
        return Outcome(template=template, details=f"Here's how I can help:\n{lines}",
                       facts=self.facts(turn, "capabilities", assistant_capabilities=CAPABILITIES), use_model=False,
                       actions=[reply("Explain the current diagnosis")] if self.diagnosis_line(turn.incident) else [])

    async def on_knowledge(self, turn: Turn) -> Outcome:
        context = turn.state.context
        concepts = explain_concepts(turn.user.content)
        site = None if concepts or not context.site_ids else context.site_ids[0]
        query = KnowledgeQuery(text=turn.user.content[:4000], site_id=site, limit=3)
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
        details_text: str | None = None
        if concepts:
            names = [name for name, _ in concepts]
            body = "\n\n".join(f"**{name}**: {definition}" for name, definition in concepts)
            summary = comparison(names)
            related = [d for d in documents if any(name.lower() in d["title"].lower() or name.lower() in d["excerpt"].lower()
                                                   for name in names)][:2]
            more = ("\n\nRelated guidance in the knowledge base: " + ", ".join(f"**{d['title']}** (`{d['record_id']}`)" for d in related)
                    if related else "")
            template = ("This is general networking background, not evidence from this incident.\n\n" + body
                        + (f"\n\n{summary}" if summary else "") + more)
            documents = related
        elif documents:
            listed = "\n".join(f"- **{d['title']}** (`{d['record_id']}`)" for d in documents)
            template = (f"The closest guide is **{documents[0]['title']}** (`{documents[0]['record_id']}`)"
                        + (f", plus {len(documents) - 1} more" if len(documents) > 1 else "") + ". It's guidance, not evidence.")
            details_text = f"Knowledge base matches (troubleshooting guidance, not evidence from this incident):\n{listed}"
        else:
            template = "I couldn't find a matching playbook or runbook. Tell me what users are seeing and I'll help narrow it down."
        return Outcome(template=template, details=details_text, facts=self.facts(turn, "knowledge_question", knowledge_base=documents,
                                                           general_concepts=[{"term": n, "definition": d} for n, d in concepts],
                                                           knowledge_notice="Unverified guidance; not evidence."),
                       knowledge_searches=1)

    async def on_incident_query(self, turn: Turn) -> Outcome:
        incident = turn.incident
        if incident is None:
            return Outcome(template="This conversation isn't linked to an incident. Open one from the incidents list, or describe what users "
                                    "are seeing and I'll help from there.", facts=self.facts(turn, "incident_question"))
        text = turn.user.content.lower()
        actions: list[SuggestedAction] = []
        evidence: list[EvidenceReference] = []
        details: str | None = None
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
        elif re.search(r"\bnext\b|should (?:i|we)|recommend", text):
            return await self.next_check(turn)
        else:
            diagnosis, investigation_id, diagnosis_id = self.current_diagnosis(turn)
            facts = self.facts(turn, "incident_question")
            if re.search(r"confirm|verified", text):
                template, actions = self.confirmed_answer(turn, diagnosis, facts)
                return Outcome(template=template, facts=facts, actions=actions, use_model=False)
            if WHAT_HAPPENED.match(turn.user.content.strip()) or re.search(r"summar|overview|what happened|recap", text):
                reported = incident.created_at
                parts = [f"It was reported at {reported:%H:%M} UTC on {reported:%d %b} for {self.namer.sites(incident.site_ids)}, "
                         f"as \"{incident.title}\"."]
                parts.append(self.namer.verdict(diagnosis, self.is_confirmed(turn, diagnosis)) if diagnosis
                             else "Nobody has run a diagnosis yet.")
                template = " ".join(self.with_security(turn, facts, parts))
                actions = [reply("Explain the current diagnosis")] if diagnosis else self.propose_diagnosis(turn)
            elif diagnosis is not None:
                brief, cited = self.diagnosis_brief(turn, diagnosis, diagnosis.evidence, short=True)
                template = " ".join(self.with_security(turn, facts, [brief]))
                evidence = [reference(item, investigation_id, diagnosis_id) for item in cited[:6]]
                source = (f"the investigation I ran in this conversation ({investigation_id})" if investigation_id
                          else f"the incident's current diagnosis ({diagnosis_id})")
                details = self.diagnosis_details(turn, diagnosis, diagnosis.evidence, source, investigation_id)
                actions = [reply("Why do you think that?"), reply("What should I check next?")]
            else:
                template = (f"There's no diagnosis on {incident.incident_id} yet, so I can't say what's causing it. Want me to run one? "
                            "It's read-only.")
                actions = self.propose_diagnosis(turn)
            return Outcome(template=template, details=details, facts=facts, actions=actions, evidence=evidence)
        return Outcome(template=template, details=details, facts=self.facts(turn, "incident_question"), actions=actions,
                       evidence=evidence, use_model=False)

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
        repeated_site = "site" in missing and "site" in context.asked
        questions = {
            "site": ("I still need the site before I can pick the right checks. Which site or sites are affected?" if repeated_site
                     else "Which site or sites are the affected users at?"),
            "scope": f"Is this hitting everyone at {site}, only some users, or a single person?",
            "services": "Which services are affected: internet access, internal apps like ERP or email, DNS, or Wi-Fi sign-in?",
        }
        fresh = [item for item in missing if item not in context.asked or item == "site"]
        if not fresh:
            # Every open question was asked once already: don't ask again, proceed and say what is unknown.
            return self.ready_to_diagnose(turn, assumed=missing)
        # Adaptive clarification: one question per turn, the one that changes the investigation most (where, then what, then who).
        asked = fresh[:1]
        context.asked = list(dict.fromkeys(context.asked + asked))
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
        template = f"{restate} {question}"
        return Outcome(template=template, facts=self.facts(turn, "clarification_needed", clarification=clarification.model_dump()),
                       clarification=clarification, actions=actions)

    def restatement(self, turn: Turn) -> str:
        context = turn.state.context
        who = SCOPE_TEXT.get(context.scope or "", "users")
        who = f"{who} at {self.site_names(context.site_ids)}" if context.site_ids else f"{who} (site not given yet)"
        symptoms = [ACRONYMS.sub(lambda m: m.group(1).upper(), item) for item in context.symptoms[:1]]
        when = f" ({context.timeframe})" if context.timeframe else ""
        parts = [f"Got it: {who}" + (f", {symptoms[0]}{when}" if symptoms else "") + "."]
        if context.unaffected_site_ids:
            parts.append(f"Unaffected: {self.site_names(context.unaffected_site_ids)}.")
        return " ".join(parts)

    def ready_to_diagnose(self, turn: Turn, assumed: list[str] | None = None) -> Outcome:
        context = turn.state.context
        context.pending_clarification = None
        actions = self.propose_diagnosis(turn)
        unknown = [ASSUMED[item] for item in assumed or [] if item in ASSUMED]
        note = f" I'll treat the {' and '.join(unknown)} as unknown." if unknown else ""
        if actions:
            template = f"Thanks, that's enough to start.{note} Want me to run a full diagnosis? It's read-only."
        else:
            template = (f"{self.restatement(turn)}{note} "
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
        if pending is not None and pending.for_intent == Intent.FULL_DIAGNOSIS and context.site_ids:
            context.pending_clarification = None
            return await self.on_full_diagnosis(turn)
        entities = turn.intent.entities
        supplied = entities.scope or entities.timeframe or entities.site_ids or entities.device_ids or entities.services \
            or entities.unaffected_site_ids
        if pending is None and not supplied:
            return await self.on_general(turn)
        if pending is None and not (context.symptoms or context.notes or turn.incident is not None):
            where = self.site_names(context.site_ids) if context.site_ids else "that"
            return Outcome(template=f"Noted: {where}. What are users seeing there?", facts=self.facts(turn, "context_noted"))
        missing = self.missing_details(context)
        if missing:
            return self.clarify(turn, missing, "Thanks.")
        return self.ready_to_diagnose(turn)

    async def on_status(self, turn: Turn) -> Outcome:
        state = turn.state
        latest = next(reversed(state.investigations.values()), None)
        parts = ["Nothing's running right now."]
        details = None
        if latest is not None:
            summary = latest.summary()
            kind = {"full_diagnosis": "diagnosis", "multi_agent": "specialist review", "protocol_check": "protocol check"}.get(latest.kind,
                                                                                                                             "check")
            ended = {"completed": "finished", "partial": "finished with gaps", "failed": "failed", "cancelled": "was stopped"}.get(
                summary.status, summary.status)
            calls = summary.tool_calls
            found = (f" and pointed to {FAULT_PLAIN.get(summary.fault_domain, 'a fault')} at "
                     f"{(summary.confidence or 'unknown').replace('_', ' ')} confidence"
                     if summary.fault_domain and summary.fault_domain != "unknown" else "")
            parts.append(f"The last {kind} here {ended} after {calls} read-only call{'s' if calls != 1 else ''}{found}.")
            details = (f"Last investigation: {latest.investigation_id} ({latest.kind}, {summary.status}), {calls} tool calls, "
                       f"{summary.evidence_count} evidence items.")
        if turn.incident is not None:
            confirmed = turn.incident.classification.confirmed_fault_domain
            parts.append(f"{turn.incident.incident_id} is {turn.incident.status.value}"
                         + (f", and the cause is confirmed as {FAULT_LABEL.get(confirmed.value)}." if confirmed
                            else ", and nobody has confirmed a cause yet."))
        if state.context.pending_action is not None:
            parts.append("I'm waiting for your go-ahead on the checks I offered.")
        if state.context.pending_clarification is not None:
            parts.append(f"I still need one answer from you. {state.context.pending_clarification.question}")
        return Outcome(template=" ".join(parts), details=details, use_model=False, facts=self.facts(turn, "status", investigations=[
            i.summary().model_dump(mode="json") for i in list(state.investigations.values())[-3:]]))

    async def on_human_action(self, turn: Turn) -> Outcome:
        action = turn.intent.human_action or "confirm"
        incident = turn.incident
        if action == "remediate":
            checks = incident.active_diagnosis.diagnosis.next_checks[:2] if incident and incident.active_diagnosis else []
            listed = "".join(f"\n- `{c.command}` on {c.device_id}" for c in checks)
            template = ("I can't make changes: I'm read-only, and fixes go through your change process. "
                        "I can give you read-only verification steps instead.")
            remediation_details = (f"Read-only checks that help verify a fix:{listed}" if listed else None)
            actions = [act("open_human_action", "Escalate", {"action": "escalate"}, human=True,
                           allowed=can(turn.principal, Permission.UPDATE_INCIDENTS))] if incident else []
            actions.append(reply("Give me step-by-step troubleshooting"))
            return Outcome(template=template, details=remediation_details, facts=self.facts(turn, "remediation_refused"), actions=actions,
                           use_model=False)
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
        how = (f"Use **{button}** when you're ready." if allowed
               else f"Your role doesn't have the {permission.value} permission, so ask an incident manager.")
        template = f"That's a decision for a person, so I won't do it myself. {how}"
        actions = [act("open_human_action", button, {"action": action}, human=True, allowed=allowed,
                       reason=None if allowed else f"Requires {permission.value}")]
        return Outcome(template=template, facts=self.facts(turn, "human_action_requested", human_action=label, allowed=allowed),
                       actions=actions, confirmations=[confirmation], use_model=False)

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
            return Outcome(template="Okay, I've dropped that. Nothing ran and nothing was changed.", facts=self.facts(turn, "cancelled"),
                           use_model=False)
        return Outcome(template="There's nothing running to cancel.", facts=self.facts(turn, "nothing_to_cancel"), use_model=False)

    async def on_decline(self, turn: Turn) -> Outcome:
        turn.state.context.pending_action = None
        return Outcome(template="Okay, I won't run it. Tell me when you're ready, or ask about anything else.",
                       facts=self.facts(turn, "proposal_declined"), use_model=False)

    async def on_confirmation(self, turn: Turn) -> Outcome:
        pending = turn.state.context.pending_action
        turn.state.context.pending_action = None
        if pending is None:
            return self.reoffer(turn)
        if pending.kind in ("targeted_check", "plan"):
            turn.intent.planned_calls = list(pending.calls)
            return await self.on_targeted_diagnostic(turn)
        if pending.kind == "multi_agent":
            turn.intent.rerun = True
            return await self.on_multi_agent(turn)
        if pending.kind == "protocol":
            turn.intent.planned_calls = list(pending.calls)
            turn.intent.protocols = [c.arguments.get("protocol", "") for c in pending.calls]
            turn.intent.rerun = True
            return await self.on_protocol_check(turn)
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
            return "comes from a targeted check and isn't tied to a hypothesis"
        if item.evidence_id in diagnosis.fault.supporting_evidence_ids:
            return "supports the current hypothesis"
        if item.evidence_id in diagnosis.fault.contradictory_evidence_ids:
            return "contradicts the current hypothesis"
        for alternative in diagnosis.alternatives:
            if item.evidence_id in alternative.supporting_evidence_ids:
                return f"supports the alternative hypothesis ({FAULT_LABEL.get(alternative.fault_domain.value)})"
        return "was collected during the diagnosis but isn't cited by the hypothesis"

    async def on_evidence_explanation(self, turn: Turn) -> Outcome:
        wanted = turn.intent.entities.evidence_ids
        items, investigation_id, diagnosis_id, diagnosis = self.evidence_source(turn, wanted)
        source = (f"the investigation I ran in this conversation ({investigation_id})" if investigation_id
                  else f"the incident's current diagnosis ({diagnosis_id})")
        if not items:
            actions = self.propose_diagnosis(turn)
            return Outcome(template="There's no evidence to explain yet, because no diagnosis has run"
                                    + (" here or on the incident." if turn.incident else " in this conversation.")
                                    + (" Want me to run one?" if actions else ""),
                           facts=self.facts(turn, "no_evidence", proposal="Run a full read-only diagnosis" if actions else None),
                           actions=actions, use_model=False)
        by_id = {item.evidence_id: item for item in items}
        refs = lambda chosen: [reference(i, investigation_id, diagnosis_id) for i in chosen]  # noqa: E731
        facts_extra: dict[str, Any] = {}
        if wanted:
            found = [by_id[e] for e in wanted if e in by_id]
            unknown = [e for e in wanted if e not in by_id]
            short, parts = [], []
            for item in found:
                kind, meaning = EVIDENCE_KIND[item.evidence_type]
                on = f" on {item.device_id}" if item.device_id else ""
                when = f" at {item.timestamp.strftime('%Y-%m-%d %H:%M UTC')}" if item.timestamp else ""
                short.append(self.explain_one(item, diagnosis))
                parts.append(f"**{item.evidence_id}** is {kind} from {TOOL_LABEL.get(item.tool, item.tool).lower()}{on} "
                             f"(call {item.call_id}{when}): \"{item.summary}\". {meaning} It {self.role_of(item, diagnosis)}.")
            if unknown:
                note = f"I don't have {join(unknown)} here. The evidence runs from {items[0].evidence_id} to {items[-1].evidence_id}."
                parts.append(note)
                short.append(note)
            template = " ".join(short)
            details = "\n\n".join(parts) + f"\n\nThis comes from {source}; I didn't re-run anything."
            chosen, level = found, "detail"
            actions = [act("explain_evidence", f"Explain {i.evidence_id}", {"evidence_ids": [i.evidence_id]})
                       for i in items if i not in chosen][:2]
        else:
            text = turn.user.content
            level = "technical" if SHOW_EVIDENCE.search(text) else "detail" if DEEPER.search(text) else "brief"
            details = self.diagnosis_details(turn, diagnosis, items, source, investigation_id)
            if diagnosis is None:
                template, chosen = self.findings_brief(turn, items, level)
            elif level == "technical":
                template, chosen = self.evidence_listing(turn, diagnosis, items), items[:12]
            elif level == "detail":
                template, chosen = self.diagnosis_reasons(turn, diagnosis, items)
            else:
                template, chosen = self.diagnosis_brief(turn, diagnosis, items)
            if diagnosis is not None and level != "technical":
                template = " ".join(self.with_security(turn, facts_extra, [template]))
            actions = ([reply("Why do you think that?")] if level == "brief" else
                       [reply("Show the evidence")] if level == "detail" else [])
            if diagnosis is not None and self.open_case(diagnosis):
                actions.append(reply("What should I check next?"))
        facts = self.facts(turn, "evidence_explanation", evidence_source=source,
                           evidence=[evidence_fact(i, self.role_of(i, diagnosis)) for i in chosen[:MAX_FACT_EVIDENCE]],
                           hypothesis={"root_cause": diagnosis.fault.root_cause, "fault_domain": diagnosis.fault.fault_domain.value,
                                       "reasoning": diagnosis.fault.reasoning, "confidence": diagnosis.confidence.level.value,
                                       "confidence_explanation": diagnosis.confidence.explanation} if diagnosis else None,
                           available_evidence_range=f"{items[0].evidence_id}-{items[-1].evidence_id}", **facts_extra)
        facts["evidence_ids"] = sorted(set(facts["evidence_ids"]) | {i.evidence_id for i in chosen})
        return Outcome(template=template, details=details, facts=facts, evidence=refs(chosen), actions=actions, level=level)

    def current_diagnosis(self, turn: Turn) -> tuple[Diagnosis | None, str | None, str | None]:
        """The latest full diagnosis in this conversation, else the incident's active diagnosis."""
        state = turn.state
        for investigation_id in reversed(list(state.investigations)):
            if investigation_id in state.diagnoses and state.investigations[investigation_id].status in ("completed", "partial"):
                return state.diagnoses[investigation_id], investigation_id, None
        record = turn.incident.active_diagnosis if turn.incident else None
        return (record.diagnosis, None, record.diagnosis_id) if record else (None, None, None)

    def hypothesis_check_action(self, turn: Turn, domain: str) -> SuggestedAction | None:
        topic = HYPOTHESIS_TOPIC.get(domain)
        if topic is None or not self.can_diagnose(turn):
            return None
        calls, _, _ = Planner(self.index).plan(turn.user.content, [topic], turn.intent.entities, turn.state.context)
        if not calls:
            return None
        call = calls[0]
        return act("targeted_check", f"Check {FAULT_LABEL.get(domain, domain)} anyway",
                   {"tool": call.tool, "arguments": call.arguments}, tools=True)

    async def on_hypothesis_check(self, turn: Turn) -> Outcome:
        domain = turn.intent.hypothesis or "unknown"
        label = FAULT_LABEL.get(domain, domain)
        diagnosis, investigation_id, diagnosis_id = self.current_diagnosis(turn)
        if diagnosis is None:
            topic = HYPOTHESIS_TOPIC.get(domain)
            if topic and self.deny_tools(turn) is None:
                calls, missing, _ = Planner(self.index).plan(turn.user.content, [topic], turn.intent.entities, turn.state.context)
                if calls:
                    turn.intent.planned_calls, turn.intent.missing, turn.intent.topics = calls, missing, [topic]
                    return await self.on_targeted_diagnostic(turn)
            actions = self.propose_diagnosis(turn)
            return Outcome(template=f"I haven't collected any evidence yet, so I can't say whether it's {label}. "
                                    + ("A full diagnosis would test it alongside the other likely causes. Want me to run one?"
                                       if actions else "Tell me which site or device to look at first."),
                           facts=self.facts(turn, "hypothesis_without_evidence", hypothesis=domain,
                                            proposal="Run a full read-only diagnosis" if actions else None), actions=actions)
        prefixes = HYPOTHESIS_CODES.get(domain, ())
        pool: dict[str, EvidenceItem] = {item.evidence_id: item for item in diagnosis.evidence}
        for investigation in turn.state.investigations.values():
            pool.update({item.evidence_id: item for item in investigation.evidence})
        related = [item for item in pool.values() if item.code.startswith(prefixes)]
        fault = diagnosis.fault
        supporting = set(fault.supporting_evidence_ids)
        top = FAULT_LABEL.get(fault.fault_domain.value, fault.fault_domain.value)
        confidence = diagnosis.confidence.level.value.replace("_", " ")
        lines: list[str] = []
        cited: list[EvidenceItem] = []
        if fault.fault_domain.value == domain:
            backing = [pool[e] for e in fault.supporting_evidence_ids if e in pool][:4]
            lines.append(f"Yes, that's the current hypothesis: **{fault.root_cause}** ({confidence} confidence).")
            lines += [bullet(item) for item in backing]
            cited = backing
        else:
            lines.append("The diagnosis hasn't found a cause yet, so nothing is ruled in or out." if fault.fault_domain.value == "unknown"
                         else f"The evidence so far points elsewhere: **{fault.root_cause}** ({top}, {confidence} confidence).")
            alternative = next((a for a in diagnosis.alternatives if a.fault_domain.value == domain), None)
            if alternative is not None and alternative.contradictory_evidence_ids:
                ids = ", ".join(alternative.contradictory_evidence_ids[:4])
                lines.append(f"{label.capitalize()} was considered and is contradicted by {ids}.")
                cited += [pool[e] for e in alternative.contradictory_evidence_ids[:4] if e in pool]
            elif alternative is not None:
                lines.append(f"{label.capitalize()} remains an open alternative: {alternative.hypothesis}.")
            downstream = [item for item in related if item.evidence_id in supporting or item.code.startswith(DOWNSTREAM_CODES)]
            separate = [item for item in related if item not in downstream]
            if downstream:
                ids = ", ".join(item.evidence_id for item in downstream[:4])
                lines.append(f"The {label} findings ({ids}) fit that hypothesis: they are what the {top} fault looks like from "
                             f"{self.site_names(turn.state.context.site_ids)}, not a separate {label} fault.")
                cited += downstream[:3]
            if separate:
                lines.append(f"These {label} findings are not explained by the hypothesis and are worth a look:")
                lines += [bullet(item) for item in separate[:3]]
                cited += separate[:3]
            if not related and alternative is None:
                lines.append(f"Nothing collected so far implicates {label}.")
            path = diagnosis.affected_path
            if path and path.reachability == "unreachable" and domain in BEYOND_THE_SITE and fault.device_ids:
                lines.append(f"The path from {path.source} to {path.destination} breaks at {', '.join(fault.device_ids)}, so "
                             f"traffic from the site never reaches {BEYOND_THE_SITE[domain]}.")
        source = (f"the diagnosis in this conversation ({investigation_id})" if investigation_id
                  else f"the incident's current diagnosis ({diagnosis_id})")
        lines.append(f"This is from {source}; I haven't run anything new.")
        verdict = self.namer.verdict(diagnosis, self.is_confirmed(turn, diagnosis), with_ids=True)
        if fault.fault_domain.value == domain:
            short = f"Yes, that's the current hypothesis. {verdict}"
        elif fault.fault_domain.value == "unknown":
            short = ("I can't say yet. The diagnosis hasn't found a cause, and "
                     + (f"nothing collected so far implicates {label}." if not related
                        else f"the {label} findings so far aren't enough to call it."))
        else:
            short = f"Probably not. The evidence points elsewhere. {verdict}"
            reason = next((line for line in lines[1:] if not line.startswith("- ") and not line.startswith("This is from")), None)
            if reason and len(reason) < 220:
                short += f" {reason}"
        actions = [a for a in [self.hypothesis_check_action(turn, domain)] if a is not None and fault.fault_domain.value != domain]
        facts = self.facts(turn, "hypothesis_check", hypothesis=domain, evidence_source=source,
                           current_hypothesis={"root_cause": fault.root_cause, "fault_domain": fault.fault_domain.value,
                                               "confidence": diagnosis.confidence.level.value},
                           evidence=[evidence_fact(item) for item in cited[:MAX_FACT_EVIDENCE]],
                           proposal=actions[0].label if actions else None)
        facts["evidence_ids"] = sorted(set(facts["evidence_ids"]) | {item.evidence_id for item in cited})
        return Outcome(template=first_mention(short), details="\n".join(lines), facts=facts, actions=actions,
                       evidence=[reference(item, investigation_id, diagnosis_id) for item in cited[:MAX_FACT_EVIDENCE]])

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

    def start_investigation(self, turn: Turn, kind: Literal["full_diagnosis", "targeted_check", "multi_agent", "protocol_check"],
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
        self.adopt_evidence(turn.state, investigation)
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
        if intent.broad and intent.source not in ("pending_action", "quick_action") and not intent.planned_calls:
            return self.propose_broad(turn)
        calls = [c for c in intent.planned_calls if c.tool in REGISTRY][:4]
        if not calls:
            if intent.missing:
                return self.targeted_clarification(turn, intent.missing)
            return Outcome(template="I couldn't work out which check you meant. Name the device and what to look at, for example "
                                    "\"check SIN-RTR-01 routing\".", facts=self.facts(turn, "unclear_check"))
        context = turn.state.context
        context.last_topics = list(dict.fromkeys(intent.topics or [TOOL_TOPIC[c.tool] for c in calls if c.tool in TOOL_TOPIC]))
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
                                    cancel_event=turn.handle.cancel_event, evidence_offset=turn.state.evidence_seq)
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
        short: list[str] = []
        evidence_items: list[tuple[EvidenceItem, str]] = []
        summaries: dict[int, str] = {}
        for call in calls:
            arguments = call.arguments
            endpoints = [str(arguments[key]) for key in ("source", "destination") if arguments.get(key)]
            target = arguments.get("device_id") or arguments.get("site_id") or (" -> ".join(endpoints) if endpoints else "the whole network")
            if id(call) in reused:
                previous, step = reused[id(call)]
                items = [i for i in previous.evidence if i.evidence_id in step.evidence_ids]
                source_id, ok = previous.investigation_id, True
                summaries[id(call)] = step.summary or "completed"
                lines.append(f"**{TOOL_LABEL[call.tool]} for {target}**: I already ran this in {previous.investigation_id} "
                             f"({step.call_id}), so I'm reusing that result: {step.summary}.")
                short.append(f"{TOOL_LABEL[call.tool]} for {target} (from the earlier check): {step.summary}.")
            else:
                record = next(r for r, c in zip(records, fresh) if c is call)
                items = [i for i in investigation.evidence if i.call_id == record.call_id]
                source_id, ok = investigation.investigation_id, record.succeeded
                summaries[id(call)] = digest(record)
                lines.append(f"**{TOOL_LABEL[call.tool]} for {target}** ({record.call_id}): {summaries[id(call)]}.")
            evidence_items += [(i, source_id) for i in items]
            findings = [i for i in items if i.evidence_type != EvidenceType.RECORD]
            if id(call) not in reused:
                cited = f" ({findings[0].evidence_id})" if findings else ""
                short.append(f"{TOOL_LABEL[call.tool]} for {target}: {summaries[id(call)]}{cited}.")
            lines += [bullet(i) for i in findings[:4]]
            if not findings and ok:
                lines.append("- No fault findings in this result.")
        if intent.missing:
            question = self.targeted_clarification(turn, intent.missing).template
            lines.append(f"I skipped part of the request because I need more detail: {question}")
            short.append(question)
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
        return Outcome(template="\n".join(short), details="\n".join(lines), facts=facts, investigation=investigation,
                       evidence=[reference(i, inv) for i, inv in chosen], actions=actions)

    def diagnosis_report(self, turn: Turn) -> str:
        context = turn.state.context
        parts = list(context.notes[-4:])
        if context.unaffected_site_ids:
            parts.append(f"{self.site_names(context.unaffected_site_ids)} reported unaffected.")
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
                         observer=turn.observer, cancel_event=turn.handle.cancel_event, evidence_offset=state.evidence_seq)
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
        investigation.reasoning = await run_in_threadpool(self.reason, turn, run.diagnosis, investigation.evidence,
                                                          checks_from_records(run.records))
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
        reasoning = investigation.reasoning
        calibrated = reasoning.self_evaluation.calibrated_confidence if reasoning else confidence
        short = self.namer.verdict(diagnosis, False, confidence=calibrated)
        if self.open_case(diagnosis) or report.fault_domain.value == "unknown":
            short += (f" I ran {calls} read-only check{'s' if calls != 1 else ''} and nothing explains "
                      f"{self.reported_problem(turn)}.")
        elif supporting:
            clauses = [text for text, _ in self.namer.grouped(supporting, offices=self.offices(turn))][:1]
            short += f" The main sign is that {clauses[0]}." if clauses else ""
        if investigation.fallback_used:
            short += " The AI model didn't finish, so the rule-based diagnosis produced this result."
        if reasoning is not None:
            worry = next((c for c in reasoning.contradictions if c.severity in ("strong", "moderate")), None)
            if worry is not None:
                short += f" One thing doesn't fit. {sentence(worry.statement)}"
            elif reasoning.self_evaluation.verdict in ("weak", "review"):
                short += " Treat it as provisional, because a self-check flagged it for review."
        security = self.security_line(turn)
        if security:
            short += f" {security}"
        short += " Want the evidence, or what to check next?"
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
        actions: list[SuggestedAction] = []
        confirmations: list[HumanConfirmation] = []
        if supporting:
            actions.append(act("explain_evidence", f"Explain {supporting[0].evidence_id}", {"evidence_ids": [supporting[0].evidence_id]}))
        attachments: list[Attachment] = []
        if reasoning is not None:
            lines += ["", self.reasoning_lines(reasoning)]
            attachments.append(self.reasoning_attachment(reasoning))
            offer = self.offer_plan(turn, reasoning) if (reasoning.uncertainty["level"] != "low"
                                                         or reasoning.self_evaluation.verdict in ("weak", "review")) else None
            if offer is not None:
                actions.append(offer)
        actions.append(reply("Give me step-by-step troubleshooting"))
        if incident is not None:
            actions.append(reply("Draft a customer update"))
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
        facts = self.facts(turn, "full_diagnosis", tools_ran_this_turn=True, warnings=[security] if security else [], diagnosis={
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
        if reasoning is not None:
            facts["reasoning"] = reasoning.compact()
        lines += ["", footer]
        return Outcome(template=short, details="\n".join(lines), facts=facts, investigation=investigation, confirmations=confirmations,
                       evidence=[reference(i, investigation.investigation_id) for i in supporting], actions=actions,
                       footer="Nobody has confirmed this yet, and nothing was changed.", attachments=attachments)

    # ---------- diagnostic reasoning ----------

    def scope_of(self, turn: Turn) -> Scope:
        context = turn.state.context
        text = " ".join(context.notes[-3:]) + " " + (turn.incident.description if turn.incident else "")
        return Scope(context.scenario_id or "BASELINE", tuple(context.site_ids[:5]), tuple(context.services[:5]),
                     tuple(context.device_ids[:10]), tuple(context.unaffected_site_ids[:5]), text[:2000])

    def reason(self, turn: Turn, diagnosis: Diagnosis | None, evidence: list[EvidenceItem], ran: list[PlannedCheck]) -> ReasoningReport:
        """The reasoning report for an evidence set. Related incidents come only from incidents this user may see."""
        context = turn.state.context
        onset = load_scenario(context.scenario_id).scenario.onset_at if context.scenario_id else None
        conclusion = None
        if diagnosis is not None:
            conclusion = {"fault_domain": diagnosis.fault.fault_domain.value, "device_ids": diagnosis.fault.device_ids,
                          "supporting_evidence_ids": diagnosis.fault.supporting_evidence_ids, "root_cause": diagnosis.fault.root_cause,
                          "confidence": diagnosis.confidence.level.value}
        current = others = None
        if turn.incident is not None:
            current = {"incident_id": turn.incident.incident_id, "site_ids": turn.incident.site_ids, "created_at": turn.incident.created_at,
                       "devices": diagnosis.fault.device_ids if diagnosis else []}
            try:
                summaries = self.services.secured_incidents.list_incidents(turn.principal, IncidentFilter(limit=50))
                others = [{"incident_id": i.incident_id, "title": i.title, "site_ids": i.site_ids, "created_at": i.created_at,
                           "devices": i.device_ids} for i in summaries]
            except Exception:
                others = []
        return analyze(evidence, self.scope_of(turn), onset, ran, conclusion, current_incident=current, other_incidents=others)

    def reasoning_for(self, turn: Turn, investigation_id: str | None = None) -> ReasoningReport | None:
        state = turn.state
        if investigation_id and investigation_id in state.investigations and state.investigations[investigation_id].reasoning:
            return state.investigations[investigation_id].reasoning
        latest = next((i for i in reversed(state.investigations.values()) if i.reasoning is not None), None)
        if latest is not None:
            return latest.reasoning
        record = turn.incident.active_diagnosis if turn.incident else None
        if record is not None and turn.state.context.scenario_id:
            return self.reason(turn, record.diagnosis, record.diagnosis.evidence, [])
        return None

    @staticmethod
    def reasoning_lines(reasoning: ReasoningReport) -> str:
        odds = ", ".join(f"{h.label} {percent(h.probability)}" for h in reasoning.hypotheses[:3])
        specialists = "; ".join(f"{s.title.split()[0]}: {s.verdict}" for s in reasoning.specialists)
        lines = [f"Probabilities: {odds}.", f"Uncertainty: {reasoning.uncertainty['statement']}", f"Specialists: {specialists}.",
                 f"Self-check: {reasoning.self_evaluation.verdict} (calibrated confidence {reasoning.self_evaluation.calibrated_confidence})."]
        if reasoning.causal.chain:
            lines.append("Causal chain: " + " → ".join(f"{c['evidence_id']} {c['code'].lower().replace('_', ' ')}" for c in reasoning.causal.chain))
        if reasoning.contradictions:
            lines.append("Contradictions: " + " ".join(c.statement for c in reasoning.contradictions[:2]))
        if reasoning.related_incidents:
            lines.append("Possibly related: " + "; ".join(f"{r.incident_id} ({r.relation})" for r in reasoning.related_incidents[:2]))
        return "\n".join(lines)

    @staticmethod
    def reasoning_attachment(reasoning: ReasoningReport) -> Attachment:
        return Attachment(kind="reasoning", title="How I reached this", data={
            "hypotheses": [h.model_dump(mode="json") for h in reasoning.hypotheses[:4]],
            "uncertainty": reasoning.uncertainty, "chain": reasoning.causal.chain[:6], "coverage": reasoning.causal.coverage,
            "contradictions": [c.model_dump(mode="json") for c in reasoning.contradictions[:4]],
            "specialists": [{"agent": s.agent, "title": s.title, "verdict": s.verdict, "probability": s.probability,
                             "statement": s.statement} for s in reasoning.specialists],
            "self_evaluation": reasoning.self_evaluation.model_dump(mode="json"),
            "explanation": reasoning.explanation.model_dump(mode="json"),
            "cross_layer": {k: reasoning.cross_layer[k] for k in ("lowest_failing_layer", "conclusion_layer", "assessment")},
            "related_incidents": [r.model_dump(mode="json") for r in reasoning.related_incidents[:3]],
            "plan": [p.model_dump(mode="json") for p in reasoning.plan[:3]],
        })

    def offer_plan(self, turn: Turn, reasoning: ReasoningReport, limit: int = 2) -> SuggestedAction | None:
        """User-approved execution: the planner's next checks are offered, never run until the user says so."""
        if not self.can_diagnose(turn) or not reasoning.plan:
            return None
        steps = reasoning.plan[:limit]
        calls = [PlannedCall(tool=s.tool, arguments=s.arguments, reason=s.purpose) for s in steps]
        turn.state.context.plan = calls
        turn.state.context.pending_action = PendingAction(kind="plan", calls=calls, proposed_at=now())
        return act("run_plan", f"Run {len(calls)} more check{'s' if len(calls) != 1 else ''}",
                   {"calls": [{"tool": c.tool, "arguments": c.arguments} for c in calls]}, tools=True)

    # ---------- customer communication ----------

    def customer_facts(self, turn: Turn) -> assist.Facts:
        incident = turn.incident
        context = turn.state.context
        diagnosis, _, _ = self.current_diagnosis(turn)
        confirmed = incident.classification.confirmed_fault_domain if incident else None
        domain = diagnosis.fault.fault_domain.value if diagnosis else None
        services = list(context.services)
        if not services and incident is not None:
            text = incident.description + ". " + ". ".join(incident.symptoms)
            services = [s for s in self.understand_services(text) if not unaffected(s, text)]
        return assist.Facts(
            incident_id=incident.incident_id if incident else None, title=incident.title if incident else None,
            sites=list(incident.site_ids if incident else context.site_ids), services=services,
            symptoms=list(incident.symptoms if incident else context.symptoms), status=incident.status.value if incident else None,
            severity=incident.severity.value if incident else None, priority=incident.priority.value if incident else None,
            reported_at=incident.created_at if incident else None, root_cause=diagnosis.fault.root_cause if diagnosis else None,
            root_cause_confirmed=bool(confirmed and domain and confirmed.value == domain),
            fault_label=FAULT_LABEL.get(confirmed.value if confirmed else domain or "unknown"),
            diagnosis_confidence=diagnosis.confidence.level.value if diagnosis else None,
            cause_supported=not self.open_case(diagnosis))

    def understand_services(self, text: str) -> list[str]:
        from app.conversation.entities import extract
        return extract(text, self.index).services

    async def on_customer_email(self, turn: Turn) -> Outcome:
        context = turn.state.context
        context.draft_audience = turn.intent.audience or context.draft_audience
        context.draft_tone = turn.intent.tone or context.draft_tone
        facts = self.customer_facts(turn)
        short = bool(SHORTER.search(turn.user.content))
        draft = assist.draft_email(facts, context.draft_audience, context.draft_tone, short=short)
        issues = assist.draft_issues(draft, facts)
        if issues:
            logger.warning("Email draft failed validation: %s", "; ".join(issues))
        who = "the team" if context.draft_audience == "internal" else "the customer"
        lead = "Here's a shorter version." if short else f"Here's a draft for {who}."
        template = (f"{lead} It hasn't been sent. Fill in {join(draft['placeholders'][:3])} before you send it."
                    f"\n\n**Subject:** {draft['subject']}\n\n{draft['body']}")
        other = "internal" if context.draft_audience == "customer" else "customer"
        actions = [reply("Make it more formal" if context.draft_tone == "friendly" else "Make it friendlier"),
                   reply(f"Write the {other} version")]
        return Outcome(template=template, use_model=False, actions=actions,
                       facts=self.facts(turn, "customer_email", draft={k: draft[k] for k in ("subject", "audience", "stage", "status")},
                                        validation_issues=issues),
                       attachments=[Attachment(kind="email_draft", title=draft["subject"], data=draft | {"validation_issues": issues})])

    async def on_customer_update(self, turn: Turn) -> Outcome:
        context = turn.state.context
        context.draft_audience = turn.intent.audience or context.draft_audience
        facts = self.customer_facts(turn)
        draft = assist.draft_update(facts, context.draft_audience)
        issues = assist.draft_issues(draft, facts)
        template = f"Here's an update you can post. I haven't sent or posted it.\n\n{draft['body']}"
        return Outcome(template=template, use_model=False, actions=[reply("Write it as an email")],
                       facts=self.facts(turn, "customer_update", draft={"stage": draft["stage"], "status": draft["status"]},
                                        validation_issues=issues),
                       attachments=[Attachment(kind="customer_update", title=draft["title"], data=draft | {"validation_issues": issues})])

    # ---------- step-by-step troubleshooting ----------

    def guide_target(self, turn: Turn) -> tuple[str | None, str | None]:
        entities = turn.intent.entities
        context = turn.state.context
        device = entities.device_ids[0] if entities.device_ids else None
        # A device id like DC1-FW-01 also names its site; for a core or data-centre device keep the user site in context,
        # since the useful commands depend on which users are affected.
        named = [s for s in entities.site_ids if not (device and s == self.index.devices[device].site_id and s in ("CORE", "DC1"))]
        site = (named or context.site_ids or (turn.incident.site_ids if turn.incident else []) or [None])[0]
        return site, device

    async def on_troubleshooting(self, turn: Turn) -> Outcome:
        context = turn.state.context
        if NEXT_CHECK.search(turn.user.content) and not STEPS_WANTED.search(turn.user.content):
            return await self.next_check(turn)
        if self.after_protocol_check(turn) and (protocol := self.protocol_commands(turn)):
            steps = [{"number": n, "device_id": c["device_id"], "platform": c["platform"], "title": c["purpose"], "command": c["command"],
                      "expected_healthy": c["expected_healthy"], "expected_fault": c["expected_fault"], "if_fault": c["if_fault"],
                      "if_healthy": c["if_healthy"], "domain": c["domain"], "tool_equivalent": None} for n, c in enumerate(protocol, start=1)]
            guide = {"title": "Read-only troubleshooting for the protocol findings", "site_id": context.site_ids[0] if context.site_ids else None,
                     "device_id": None, "domain": None, "steps": steps, "current": 1,
                     "notice": "Every command is read-only. Changes, if needed, go through your change process."}
            context.guide = guide
            return Outcome(template=f"Here are {len(steps)} read-only steps for the protocol findings:\n\n" + assist.render_guide(guide)
                                    + "\n\nPaste any output and I'll tell you what it means.", use_model=False,
                           facts=self.facts(turn, "troubleshooting"), attachments=[Attachment(kind="troubleshooting_guide", title=guide["title"], data=guide)])
        site, device = self.guide_target(turn)
        grounds = self.grounds(turn)
        plan = assist.plan_checks(grounds, site, device)
        guide = assist.troubleshooting_guide(site, list(context.services), device, grounds.domain, grounds=grounds)
        if not guide["steps"]:
            return self.more_evidence(turn, grounds)
        context.guide = guide | {"current": 1}
        template = (f"{self.guide_lead(grounds, plan, len(guide['steps']))}\n\n" + assist.render_guide(guide)
                    + "\n\nPaste any output and I'll tell you what it means.")
        actions = []
        runnable = assist.runnable(guide["steps"], set(REGISTRY))[:3]
        if runnable and self.can_diagnose(turn):
            calls = [PlannedCall(tool=s["tool_equivalent"]["tool"], arguments=s["tool_equivalent"]["arguments"],
                                 reason=f"Step {s['number']}: {s['title']}") for s in runnable]
            context.pending_action = PendingAction(kind="plan", calls=calls, proposed_at=now())
            numbers = join(str(s["number"]) for s in runnable)
            template += f" I can also run steps {numbers} for you as read-only checks. Just say go ahead."
            actions.append(act("run_plan", f"Run steps {numbers} for me", {"calls": [{"tool": c.tool, "arguments": c.arguments}
                                                                                      for c in calls]}, tools=True))
        facts, refs = self.grounded(turn, "troubleshooting", grounds, plan)
        return Outcome(template=template, use_model=False, actions=actions, facts=facts, evidence=refs,
                       attachments=[Attachment(kind="troubleshooting_guide", title=guide["title"], data=guide)])

    async def on_commands(self, turn: Turn) -> Outcome:
        context = turn.state.context
        if self.after_protocol_check(turn) and (protocol := self.protocol_commands(turn)):
            listed = "\n".join(f"{n}. `{c['command']}` on {c['device_id']} ({c['platform']}): {c['purpose'].rstrip('.')}. Healthy: {c['expected_healthy']}."
                               for n, c in enumerate(protocol, start=1))
            return Outcome(template=f"Read-only commands for the protocol findings:\n{listed}", use_model=False,
                           facts=self.facts(turn, "commands"),
                           attachments=[Attachment(kind="commands", title="Read-only commands for the protocol findings", data={"commands": protocol})])
        site, device = self.guide_target(turn)
        device = device or context.focus_device_id
        grounds = self.grounds(turn)
        plan = assist.plan_checks(grounds, site, device)
        commands = plan.commands
        if not commands:
            return self.more_evidence(turn, grounds)
        target = device or self.namer.site(site) if (device or site) else "this incident"
        listed = "\n".join(f"{n}. `{c.command}` on {c.device_id}: {c.purpose.rstrip('.')}. Healthy: {c.healthy}."
                           for n, c in enumerate(commands, start=1))
        lead = self.guide_lead(grounds, plan, len(commands)).replace("steps", "commands").replace("step", "command") \
            if not device else f"Read-only commands for {target}:"
        facts, refs = self.grounded(turn, "commands", grounds, plan)
        return Outcome(template=f"{lead}\n{listed}", use_model=False, facts=facts, evidence=refs,
                       attachments=[Attachment(kind="commands", title=f"Read-only commands for {target}",
                                               data={"commands": [c.as_dict() for c in commands]})])

    def guide_step(self, turn: Turn, command: str | None = None, number: int | None = None) -> dict | None:
        guide = turn.state.context.guide
        if not guide:
            return None
        steps = guide["steps"]
        if number is not None:
            return next((s for s in steps if s["number"] == number), None)
        if command:
            return next((s for s in steps if s["command"].startswith(command)), None)
        return None

    async def on_output_interpretation(self, turn: Turn) -> Outcome:
        result = assist.interpret(turn.user.content)
        if result["verdict"] == "error":
            return await self.on_step_failed(turn)
        context = turn.state.context
        step = self.guide_step(turn, command=result["command"]) or self.guide_step(turn, number=turn.intent.step)
        template = result["summary"]
        if step is not None:
            follow = step["if_fault"] if result["verdict"] == "fault" else step["if_healthy"] if result["verdict"] == "healthy" else None
            if follow:
                template += f" Next: {follow}"
            context.guide = context.guide | {"current": min(len(context.guide["steps"]), step["number"] + 1)}
        if result["security_flags"]:
            template += " (I ignored instructions inside the pasted text; it's treated as data.)"
        return Outcome(template=template, use_model=False, facts=self.facts(turn, "output_interpretation"),
                       attachments=[Attachment(kind="output_interpretation", title=f"Reading of {result['command'] or 'the output'}",
                                               data=result | {"step": step["number"] if step else None})])

    async def on_step_failed(self, turn: Turn) -> Outcome:
        step = self.guide_step(turn, number=turn.intent.step) if turn.intent.step else None
        help_ = assist.failure_help(turn.user.content, step)
        template = f"{help_['reason']} {help_['advice']}"
        if help_["alternative"]:
            template += f" Try `{help_['alternative']['command']}` on {help_['alternative']['device_id']}."
        guide = turn.state.context.guide
        if step and guide and step["number"] < len(guide["steps"]):
            template += f" Or skip to step {step['number'] + 1}."
        return Outcome(template=template, use_model=False, facts=self.facts(turn, "step_failed"),
                       actions=[reply("Next step")] if guide else [])

    async def on_detail(self, turn: Turn) -> Outcome:
        previous = next((m for m in reversed(turn.state.messages[:-1]) if m.role == "assistant"), None)
        if (previous is None or not previous.details) and (TECHNICAL_ASK.search(turn.user.content) or previous is None):
            items, investigation_id, diagnosis_id, diagnosis = self.evidence_source(turn, [])
            if diagnosis is not None and items:
                source = (f"the investigation I ran in this conversation ({investigation_id})" if investigation_id
                          else f"the incident's current diagnosis ({diagnosis_id})")
                facts = self.facts(turn, "detail")
                facts["evidence_ids"] = sorted(set(facts["evidence_ids"]) | {i.evidence_id for i in items})
                return Outcome(template=self.evidence_listing(turn, diagnosis, items), use_model=False, level="technical", facts=facts,
                               details=self.diagnosis_details(turn, diagnosis, items, source, investigation_id),
                               evidence=[reference(i, investigation_id, diagnosis_id) for i in items[:12]])
        if previous is None or not previous.details:
            return Outcome(template="That's everything I have on it. Want the evidence or step-by-step troubleshooting?",
                           facts=self.facts(turn, "no_more_detail"))
        facts = self.facts(turn, "detail")
        known = {i.evidence_id for inv in turn.state.investigations.values() for i in inv.evidence}
        if turn.incident and turn.incident.active_diagnosis:
            known |= {i.evidence_id for i in turn.incident.active_diagnosis.diagnosis.evidence}
        facts["evidence_ids"] = sorted(set(facts["evidence_ids"]) | known | {r.evidence_id for r in previous.evidence_refs})
        return Outcome(template=previous.details, use_model=False, facts=facts,
                       evidence=list(previous.evidence_refs), attachments=list(previous.attachments))

    async def on_continue(self, turn: Turn) -> Outcome:
        context = turn.state.context
        guide = context.guide
        if guide and guide.get("current", 1) <= len(guide["steps"]):
            index = guide.get("current", 1)
            step = guide["steps"][index - 1]
            context.guide = guide | {"current": index + 1}
            return Outcome(template=f"Step {step['number']} of {len(guide['steps'])}:\n\n" + assist.render_guide(guide, index - 1, 1),
                           use_model=False, facts=self.facts(turn, "guide_step"))
        reasoning = self.reasoning_for(turn)
        offer = self.offer_plan(turn, reasoning, limit=1) if reasoning is not None else None
        if offer is not None:
            return Outcome(template=f"Next I'd {reasoning.plan[0].purpose[0].lower()}{reasoning.plan[0].purpose[1:]} Want me to run it?",
                           facts=self.facts(turn, "plan_offered", proposal=offer.label), actions=[offer, reply("Not yet")])
        if turn.state.investigations:
            return Outcome(template="Nothing's left to run. I can draft a customer update or give step-by-step troubleshooting.",
                           facts=self.facts(turn, "nothing_next"),
                           actions=[reply("Draft a customer update"), reply("Give me step-by-step troubleshooting")])
        actions = self.propose_diagnosis(turn)
        return Outcome(template="We haven't started yet. Want me to run a full diagnosis?" if actions
                       else "We haven't started yet. Tell me what users are seeing.", facts=self.facts(turn, "nothing_started"),
                       actions=actions)

    # ---------- specialists and multi-agent investigation ----------

    async def on_specialist_review(self, turn: Turn) -> Outcome:
        name = turn.intent.specialist
        reasoning = self.reasoning_for(turn)
        if reasoning is None:
            agent = AGENTS.get(name or "transport")
            scope = self.scope_of(turn)
            checks = agent.plan(scope)[:3] if scope.site_ids else []
            if not checks or not self.can_diagnose(turn):
                return Outcome(template="There's no evidence for the specialists to review yet. Want me to run a diagnosis?",
                               facts=self.facts(turn, "no_evidence"), actions=self.propose_diagnosis(turn))
            calls = [PlannedCall(tool=c.tool, arguments=c.arguments, reason=c.reason) for c in checks]
            turn.state.context.pending_action = PendingAction(kind="plan", calls=calls, proposed_at=now())
            return Outcome(template=f"The {agent.title.lower()} would start with {len(calls)} read-only checks: "
                                    + "; ".join(c.reason.rstrip("?") for c in checks) + ". Want me to run them?",
                           facts=self.facts(turn, "specialist_plan", proposal="Run the specialist's checks"),
                           actions=[act("run_plan", "Run them", {"calls": [{"tool": c.tool, "arguments": c.arguments} for c in calls]},
                                        tools=True), reply("Not yet")])
        views = [s for s in reasoning.specialists if name is None or s.agent == name]
        template = " ".join(f"{s.title}: {s.statement}" for s in views[:4])
        details = "\n".join(f"- **{s.title}** ({s.verdict}, {percent(s.probability)}): {s.statement}"
                            + (f" Evidence: {', '.join(s.evidence_ids[:3])}." if s.evidence_ids else "") for s in views)
        facts = self.facts(turn, "specialist_review")
        facts["evidence_ids"] = sorted(set(facts["evidence_ids"]) | {e for s in views for e in s.evidence_ids})
        return Outcome(template=template, details=details, facts=facts,
                       attachments=[Attachment(kind="specialists", title="Specialist reviews",
                                               data={"specialists": [s.model_dump(mode="json") for s in views]})])

    async def on_multi_agent(self, turn: Turn) -> Outcome:
        denied = self.deny_tools(turn)
        if denied is not None:
            return denied
        state, context = turn.state, turn.state.context
        if not context.site_ids:
            clarification = Clarification(question="Which site should the specialists look at?", missing=["site"],
                                          options=[self.index.site_names[s] for s in sorted(self.index.site_names)])
            context.pending_clarification = PendingClarification(for_intent=Intent.FULL_DIAGNOSIS, question=clarification.question,
                                                                 missing=["site"])
            return Outcome(template=clarification.question, clarification=clarification,
                           facts=self.facts(turn, "clarification_needed", clarification=clarification.model_dump()))
        scope = self.scope_of(turn)
        fingerprint = hashlib.sha256(f"team|{scope}".encode()).hexdigest()
        if not turn.intent.rerun:
            for investigation_id, previous_print in reversed(state.fingerprints.items()):
                previous = state.investigations.get(investigation_id)
                if previous_print == fingerprint and previous is not None and previous.reasoning is not None:
                    return Outcome(template=f"The specialists already looked at exactly this ({investigation_id}): "
                                            f"{previous.reasoning.explanation.summary} Say \"run it again\" for a fresh run.",
                                   facts=self.facts(turn, "team_reused"), actions=[act("multi_agent", "Run it again", tools=True)])
        investigation = self.start_investigation(turn, "multi_agent", "direct")
        state.fingerprints[investigation.investigation_id] = fingerprint
        self.emit(turn, "investigation.started", {"investigation_id": investigation.investigation_id, "kind": "multi_agent",
                                                  "mode": "direct", "agents": list(AGENTS), "budget_limit": MAX_TOOL_CALLS})
        run = await asyncio.to_thread(team_investigate, scope, MAX_TOOL_CALLS, turn.observer, turn.handle.cancel_event, state.evidence_seq)
        investigation.evidence = run.evidence
        investigation.budget_used = len(run.records)
        investigation.reasoning = await run_in_threadpool(self.reason, turn, None, run.evidence, run.executed)
        self.close_investigation(turn, investigation, "completed" if all(r.succeeded for r in run.records) else "partial")
        reasoning = investigation.reasoning
        if reasoning.fault_supported:
            lead = reasoning.hypotheses[0]
            implicated = next((s for s in reasoning.specialists if s.verdict == "implicated"), None)
            template = (f"The specialists point to **{lead.label}** ({percent(lead.probability)}, "
                        f"{reasoning.self_evaluation.calibrated_confidence} confidence)."
                        + (f" {implicated.statement.rstrip('.')}." if implicated else "") + " Want each specialist's view?")
        elif reasoning.suspected:
            template = (f"The specialists ran {len(run.executed)} read-only checks. Nothing is confirmed, but one thing looks suspicious "
                        f"and could explain it: {reasoning.suspected[0]}. Treat it as unconfirmed until someone checks it. "
                        "Want each specialist's view?")
        else:
            template = f"The specialists ran {len(run.executed)} read-only checks and found no fault. Want each specialist's view?"
        refs = [reference(i, investigation.investigation_id) for i in run.evidence
                if reasoning.hypotheses and i.evidence_id in reasoning.hypotheses[0].supporting_evidence_ids][:6]
        facts = self.facts(turn, "multi_agent", tools_ran_this_turn=True, reasoning=reasoning.compact())
        facts["evidence_ids"] = sorted(set(facts["evidence_ids"]) | {i.evidence_id for i in run.evidence})
        return Outcome(template=template, details=self.reasoning_lines(reasoning), facts=facts, investigation=investigation,
                       evidence=refs, result_by="rule_based", attachments=[self.reasoning_attachment(reasoning)],
                       actions=[reply("What do the specialists think?"), reply("Give me step-by-step troubleshooting")])

    # ---------- Phase 3: protocol and security checks (approval first, read-only, synthetic telemetry) ----------

    def protocol_where(self, turn: Turn, calls: list[PlannedCall]) -> str:
        sites = sorted({c.arguments["site_id"] for c in calls if c.arguments.get("site_id")})
        return self.site_names(sites) if sites else "all sites"

    @staticmethod
    def protocol_names(engines: list[str]) -> str:
        names = [PROTOCOL_SHORT.get(e, e) for e in engines]
        return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"

    def protocol_calls(self, turn: Turn, engines: list[str]) -> list[PlannedCall]:
        context = turn.state.context
        site = context.site_ids[0] if len(context.site_ids) == 1 else None
        return [PlannedCall(tool="analyze_protocol", arguments={"protocol": e, **({"site_id": site} if site else {})},
                            reason=f"{PROTOCOL_SHORT.get(e, e)} check requested by you") for e in engines]

    @staticmethod
    def protocol_action(label: str, calls: list[PlannedCall]) -> SuggestedAction:
        return act("protocol", label, {"calls": [{"tool": c.tool, "arguments": c.arguments} for c in calls]}, tools=True)

    async def on_protocol_check(self, turn: Turn) -> Outcome:
        denied = self.deny_tools(turn)
        if denied is not None:
            return denied
        state, context, intent = turn.state, turn.state.context, turn.intent
        if intent.scan_refused:
            calls = self.protocol_calls(turn, ["traffic", "lateral", "threats"])
            context.pending_action = PendingAction(kind="protocol", calls=calls, proposed_at=now())
            return Outcome(template="I don't scan networks or send probes; I only read telemetry that was already collected. I can review the "
                                    "collected flow and login records for scans, suspicious traffic and lateral movement instead. Go ahead?",
                           facts=self.facts(turn, "scan_declined"), use_model=False,
                           actions=[self.protocol_action("Review the collected records", calls), reply("No thanks")])
        calls = [c for c in intent.planned_calls if c.tool == "analyze_protocol"]
        if not calls:
            engines = [e for e in intent.protocols if e in PROTOCOL_ENGINES or e == "all"]
            if not engines:
                text = " ".join(context.notes[-3:] + context.symptoms + ([turn.incident.title, turn.incident.description] if turn.incident else []))
                engines = engines_for_symptoms(text)[:4]
            if not engines:
                return Outcome(template="Which protocol should I look at? For example BGP, the OSPF database, spanning tree, ARP, trunks, NAT, "
                                        "VPN tunnels, TCP, MTU, QoS, IPv6, Wi-Fi, multicast, certificates, or a security review.",
                               facts=self.facts(turn, "protocol_unclear"), use_model=False)
            calls = self.protocol_calls(turn, engines)
        engines = [c.arguments.get("protocol", "") for c in calls][:6]
        calls = calls[:6]
        names, where = self.protocol_names(engines), self.protocol_where(turn, calls)
        fingerprint = hashlib.sha256(f"protocol|{context.scenario_id}|{sorted(str(c.arguments) for c in calls)}".encode()).hexdigest()
        approved = intent.source in ("pending_action", "quick_action")
        if not approved:
            if not intent.rerun:
                for investigation_id, previous_print in reversed(state.fingerprints.items()):
                    previous = state.investigations.get(investigation_id)
                    if previous_print == fingerprint and previous is not None and previous.protocol:
                        return Outcome(template=f"I already ran the {names} check for {where} ({investigation_id}): "
                                                f"{previous.protocol['headline']} Say \"run it again\" to refresh it.",
                                       facts=self.facts(turn, "protocol_reused", protocol={"headline": previous.protocol["headline"]}),
                                       use_model=False, actions=[self.protocol_action("Run it again", calls)])
            context.pending_action = PendingAction(kind="protocol", calls=calls, proposed_at=now())
            plural = "s" if len(engines) > 1 or engines == ["all"] else ""
            lead = f"{self.attack_answer(turn)} " if ATTACK_QUESTION.search(turn.user.content) else ""
            return Outcome(template=f"{lead}I can run the read-only {names} check{plural} for {where}. "
                                    f"{'They only read' if plural else 'It only reads'} telemetry that's already been collected. Go ahead?",
                           facts=self.facts(turn, "protocol_offer", planned=[c.arguments for c in calls]), use_model=False,
                           actions=[self.protocol_action(f"Run the {names} check{plural}" if len(engines) <= 2 else f"Run these {len(engines)} checks",
                                                         calls), reply("No thanks")])
        investigation = self.start_investigation(turn, "protocol_check", "direct")
        state.fingerprints[investigation.investigation_id] = fingerprint
        self.emit(turn, "investigation.started", {
            "investigation_id": investigation.investigation_id, "kind": "protocol_check", "mode": "direct",
            "planned": [{"tool": c.tool, "label": f"{PROTOCOL_SHORT.get(c.arguments.get('protocol'), 'Protocol')} check",
                         "arguments": c.arguments, "reason": c.reason} for c in calls], "budget_limit": MAX_TOOL_CALLS})
        executor = ToolExecutor(context.scenario_id, max_calls=MAX_TOOL_CALLS, observer=turn.observer, cancel_event=turn.handle.cancel_event,
                                evidence_offset=state.evidence_seq)
        records = [await asyncio.to_thread(executor.execute, c.tool, c.arguments) for c in calls]
        investigation.budget_used = executor.requests
        investigation.evidence = build_catalog(executor.records)
        current = others = None
        if turn.incident is not None:
            current = {"incident_id": turn.incident.incident_id, "site_ids": turn.incident.site_ids, "created_at": turn.incident.created_at,
                       "devices": []}
            try:
                summaries = self.services.secured_incidents.list_incidents(turn.principal, IncidentFilter(limit=50))
                others = [{"incident_id": i.incident_id, "title": i.title, "site_ids": i.site_ids, "created_at": i.created_at,
                           "devices": i.device_ids} for i in summaries]
            except Exception:
                others = []
        symptoms = " ".join(context.notes[-3:] + context.symptoms + ([turn.incident.title, turn.incident.description] if turn.incident else []))
        site = next((c.arguments["site_id"] for c in calls if c.arguments.get("site_id")), None)
        report = await run_in_threadpool(protocol_analyze, context.scenario_id, None if "all" in engines else engines, site, None, symptoms,
                                         current, others)
        investigation.protocol = report.model_dump(mode="json")
        self.close_investigation(turn, investigation, "completed" if all(r.succeeded for r in records) else "partial")
        evidence_of = {}
        for item in investigation.evidence:
            evidence_of.setdefault((item.code, item.device_id), item.evidence_id)
            evidence_of.setdefault((item.code, None), item.evidence_id)
        cite = {f.finding_id: evidence_of.get((f.code, f.device_id)) or evidence_of.get((f.code, None)) for f in report.findings}
        template = self.protocol_reply(report, cite, names, where)
        facts = self.facts(turn, "protocol_check", tools_ran_this_turn=True, protocol={
            "headline": report.headline, "counts": report.counts, "synthetic": True,
            "findings": [{"id": f.finding_id, "evidence_id": cite.get(f.finding_id), "code": f.code, "status": f.status, "title": f.title,
                          "device": f.device_id, "sites": f.affected_sites, "confidence": f.confidence, "hosts": f.hosts[:3]} for f in report.findings[:12]]})
        facts["evidence_ids"] = sorted(set(facts["evidence_ids"]) | {i.evidence_id for i in investigation.evidence})
        actions = []
        lead = next((f for f in report.findings if f.finding_id in (report.root_causes[:1] or report.threats[:1])), None)
        if lead is not None and cite.get(lead.finding_id):
            actions.append(act("explain_evidence", f"Explain {cite[lead.finding_id]}", {"evidence_ids": [cite[lead.finding_id]]}))
        if any(f.commands for f in report.findings):
            actions.append(reply("Show me the commands"))
        for check in report.next_checks[:2]:
            next_calls = self.protocol_calls(turn, [check.engine])
            actions.append(self.protocol_action(f"Also check {PROTOCOL_SHORT.get(check.engine, check.engine)}", next_calls))
        refs = [reference(i, investigation.investigation_id) for i in investigation.evidence[:6]]
        return Outcome(template=template, details=self.protocol_details(report, cite), facts=facts, investigation=investigation,
                       evidence=refs, use_model=False, result_by="rule_based", actions=actions,
                       attachments=[Attachment(kind="protocol", title=f"{names[:1].upper() + names[1:]} check{'s' if len(engines) > 1 else ''}",
                                               data=self.protocol_card(report, cite))])

    @staticmethod
    def protocol_reply(report, cite: dict[str, str | None], names: str, where: str) -> str:
        by_id = {f.finding_id: f for f in report.findings}

        def tag(finding) -> str:
            evidence = cite.get(finding.finding_id)
            return f" ({evidence})" if evidence else ""

        if report.root_causes:
            lead = by_id[report.root_causes[0]]
            word = PROTOCOL_STATUS[lead.status]
            evidence = f", {cite[lead.finding_id]}" if cite.get(lead.finding_id) else ""
            explained = f" It also explains {len(lead.explains)} other finding{'s' if len(lead.explains) != 1 else ''}." if lead.explains else ""
            return (f"Found it: **{lead.title}** ({word}, {lead.confidence_label} confidence{evidence}).{explained} "
                    "Want the evidence or the read-only commands?")
        if report.threats:
            lead = by_id[report.threats[0]]
            return (f"**{lead.title}**{tag(lead)}: {lead.facts.get('likelihood', 'possible')} on {len(lead.facts.get('sources', []))} independent "
                    "sources, but not confirmed. An analyst should review it; the data says nothing about who is behind it. Want the details?")
        confirmed = [f for f in report.findings if f.status == "confirmed_fault"]
        if confirmed:
            lead = confirmed[0]
            core = next((c.detail for c in lead.correlations if c.kind == "core_evidence"), None)
            if core is None and any(x.startswith("core:") for x in lead.explained_by):
                change = next((c.detail for c in lead.correlations if c.kind == "config_change"), None)
                core = f"It follows a {change[0].lower() + change[1:]}" if change else None
            if core:
                return f"**{lead.title}**{tag(lead)}, but that's an effect rather than the cause. {core.split(': ')[0]}."
            return f"**{lead.title}** (confirmed){tag(lead)}. Want the details?"
        suspicious = [f for f in report.findings if f.status == "suspicious_indicator"]
        if suspicious:
            lead = suspicious[0]
            return f"**{lead.title}**{tag(lead)}: suspicious, not confirmed. Want the details?"
        possible = [f for f in report.findings if f.status == "possible_explanation"]
        if possible:
            return f"Nothing confirmed. Possible: **{possible[0].title}**{tag(possible[0])}. Want the details?"
        missing = [f for f in report.findings if f.status == "insufficient_evidence"]
        if missing and len(missing) >= len(report.engines):
            return f"I couldn't check {names} for {where}: {missing[0].summary.rstrip('.')}."
        suppressed = " ".join(n for n in report.notes if n.startswith("Suppressed"))
        kinds = [k for k, word in (("the vulnerability scanner", "scanner"), ("the admin jump host", "jump host"), ("backups", "backup"))
                 if word in suppressed]
        return (f"The {names} check{'s' if ' and ' in names or names.startswith('protocol') else ''} found nothing wrong for {where}."
                + (f" Authorised activity from {' and '.join(kinds)} was recognised and not flagged." if kinds else "")
                + (" Some data was missing, so this isn't a full all-clear." if missing else ""))

    @staticmethod
    def protocol_details(report, cite: dict[str, str | None]) -> str:
        lines = [f"**{report.headline}**", ""]
        for f in report.findings:
            if f.status == "insufficient_evidence":
                continue
            label = PROTOCOL_STATUS[f.status].capitalize()
            confidence = f", {f.confidence_label} {f.confidence:.2f}" if f.confidence is not None else ""
            lines.append(f"- [{label}{confidence}] {f.title}{f' ({cite[f.finding_id]})' if cite.get(f.finding_id) else ''}: {f.summary}")
            for correlation in f.correlations[:2]:
                lines.append(f"  - {correlation.detail}")
        gaps = [f for f in report.findings if f.status == "insufficient_evidence"]
        if gaps:
            lines.append("Not enough data: " + "; ".join(f"{f.title}" for f in gaps[:4]) + ".")
        if report.notes:
            lines.append("Notes: " + " ".join(report.notes[:4]))
        if report.causal_chain and len(report.causal_chain) > 1:
            by_id = {f.finding_id: f for f in report.findings}
            lines.append("Chain: " + " → ".join(by_id[x].title for x in report.causal_chain if x in by_id) + ".")
        lines.append("Read-only checks on synthetic telemetry; nothing was changed and no device was contacted.")
        return "\n".join(lines)

    @staticmethod
    def protocol_card(report, cite: dict[str, str | None]) -> dict[str, Any]:
        return {"headline": report.headline, "synthetic": True, "counts": report.counts, "root_causes": report.root_causes,
                "threats": report.threats, "causal_chain": report.causal_chain, "notes": report.notes[:5], "missing": report.missing[:4],
                "hypotheses": [h.model_dump() for h in report.hypotheses],
                "engines": [{"engine": e.engine, "title": e.title, "status": e.status} for e in report.engines],
                "next_checks": [c.model_dump() for c in report.next_checks],
                "findings": [{"finding_id": f.finding_id, "evidence_id": cite.get(f.finding_id), "engine": f.engine, "code": f.code,
                              "status": f.status, "severity": f.severity, "title": f.title, "summary": f.summary, "basis": f.basis,
                              "confidence": f.confidence, "confidence_label": f.confidence_label, "device_id": f.device_id,
                              "affected_sites": f.affected_sites, "root_cause": f.root_cause, "explained_by": f.explained_by,
                              "correlations": [c.detail for c in f.correlations[:4]], "commands": [c.model_dump() for c in f.commands[:3]],
                              "evidence": [r.model_dump(mode="json") for r in f.evidence[:4]], "injection_ignored": f.injection_ignored}
                             for f in report.findings[:20]]}

    @staticmethod
    def after_protocol_check(turn: Turn) -> bool:
        """True when the most recent investigation in this conversation was a protocol check."""
        latest = next(reversed(turn.state.investigations.values()), None) if turn.state.investigations else None
        return latest is not None and latest.kind == "protocol_check" and bool(latest.protocol)

    def protocol_commands(self, turn: Turn) -> list[dict[str, Any]]:
        latest = next((i for i in reversed(turn.state.investigations.values()) if i.kind == "protocol_check" and i.protocol), None)
        if latest is None:
            return []
        findings = latest.protocol["findings"]
        ordered = [f for f in findings if f["finding_id"] in latest.protocol["root_causes"] + latest.protocol["threats"]]
        ordered += [f for f in findings if f not in ordered and f["status"] != "insufficient_evidence"]
        commands = []
        for finding in ordered:
            for c in finding["commands"]:
                commands.append({"device_id": c["device_id"], "command": c["command"], "platform": c["platform"], "purpose": c["purpose"],
                                 "expected_healthy": c["healthy"], "expected_fault": c["faulty"],
                                 "if_fault": f"That confirms {finding['title'].lower()[:1] + finding['title'][1:]}.",
                                 "if_healthy": "Recollect the telemetry; the finding may have cleared.", "domain": finding["engine"],
                                 "tool_equivalent": None})
        unique = {(c["device_id"], c["command"]): c for c in commands}
        return list(unique.values())[:6]

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
