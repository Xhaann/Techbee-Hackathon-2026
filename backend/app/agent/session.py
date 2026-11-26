import asyncio
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import openai
from agent_framework import AgentFrameworkException
from pydantic import BaseModel, ConfigDict

from app.agent.runtime import AgentModel, agent_model, build_agent, run_deadline
from app.agent.tools import KNOWLEDGE_TOOL, MAX_KNOWLEDGE_CALLS, ToolBudget
from app.core.config import Settings, get_settings
from app.engine.engine import DiagnosisEngine, ModelSession, parse_draft
from app.engine.evidence import build_catalog
from app.engine.executor import MAX_TOOL_CALLS, ToolCallRecord, ToolExecutor
from app.engine.planner import SERVICE_KEYWORDS, DiagnosisRequestError, RuleBasedPlanner, resolve_context
from app.engine.correlation import correlate
from app.engine.retrieval import NoRetrieval, Retriever
from app.engine.safety import injection_flags
from app.engine.schema import Confidence, Diagnosis, DiagnosisDraft, DiagnosisRequest
from app.knowledge import KnowledgeService
from app.network.models import DeviceRole, NetworkTopology, PathService
from app.network.repository import list_scenario_ids, load_topology
from app.security.secrets import redact

MAX_REPORT_CHARS = 4000
SERVICE_ROLES = {DeviceRole.DNS_SERVER: PathService.DNS, DeviceRole.DHCP_SERVER: PathService.DHCP,
                 DeviceRole.AUTHENTICATION_SERVER: PathService.AUTHENTICATION}
SERVICE_TERMS = {SERVICE_ROLES[role]: pattern for role, pattern in SERVICE_KEYWORDS} | {
    PathService.INTERNET: re.compile(r"\b(internet|external (sites|websites)|public web)\b", re.IGNORECASE),
    PathService.APPLICATION: re.compile(r"\b(applications?|apps?|erp|portal|corporate services?|intranet|data cent(re|er))\b", re.IGNORECASE),
}
SYMPTOM_TERMS = re.compile(
    r"\b(cannot (?:access|reach|connect|open|resolve|obtain|log ?in)\w*(?: [a-z]+){0,3}|can't (?:access|reach|connect)\w*(?: [a-z]+){0,3}"
    r"|offline|down|outage|unreachable|slow(?: [a-z]+){0,2}|packet loss|choppy(?: [a-z]+)?|timeouts?|dropp\w+(?: [a-z]+)?"
    r"|intermittent(?: [a-z]+)?|no (?:ip address|connectivity|network))\b", re.IGNORECASE)
TIMEFRAME_TERMS = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?Z?|since \d{1,2}(?::\d{2})?\s?(?:am|pm)?(?: [A-Z]{2,4})?"
    r"|(?:for|in) the (?:last|past) \d+ (?:minutes?|hours?)|\d+ (?:minutes?|hours?) ago|this (?:morning|afternoon|evening)"
    r"|yesterday|today|overnight)\b", re.IGNORECASE)
UNKNOWN = "unknown"


class AgentModelBase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class IncidentUnderstanding(AgentModelBase):
    summary: str
    sites: list[str]
    services: list[str]
    symptoms: list[str]
    timeframe: str
    devices: list[str]
    available_evidence: str
    unknown_fields: list[str]


def understand(report: str, scenario_id: str, topology: NetworkTopology, site_ids: Sequence[str] = (),
               device_ids: Sequence[str] = (), services: Sequence[PathService] = ()) -> IncidentUnderstanding:
    known_devices = {device.device_id for device in topology.devices}
    unknown = sorted(set(device_ids) - known_devices)
    if unknown:
        raise DiagnosisRequestError(f"Unknown device identifiers: {', '.join(unknown)}")
    explicit = DiagnosisRequest(scenario_id=scenario_id, description=report[:MAX_REPORT_CHARS], site_ids=list(site_ids)[:5])
    sites = resolve_context(explicit, topology).sites
    devices = sorted(set(device_ids) | {device for device in known_devices
                                        if re.search(rf"\b{re.escape(device)}\b", report, re.IGNORECASE)})
    services = list(dict.fromkeys([PathService(service).value for service in services]
                                  + [service.value for service, pattern in SERVICE_TERMS.items() if pattern.search(report)]))
    symptoms = list(dict.fromkeys(match.group(0).lower() for match in SYMPTOM_TERMS.finditer(report)))[:10]
    timeframe = next((match.group(0) for match in TIMEFRAME_TERMS.finditer(report)), UNKNOWN)
    fields = {"site": sites, "service": services, "symptoms": symptoms, "timeframe": timeframe != UNKNOWN, "devices": devices}
    return IncidentUnderstanding(
        summary=redact(" ".join(report.split()))[:500], sites=sites, services=services, symptoms=symptoms, timeframe=timeframe,
        devices=devices, available_evidence=f"Synthetic telemetry for scenario {scenario_id}, reachable only through the diagnostic tools",
        unknown_fields=[name for name, value in fields.items() if not value],
    )


@dataclass
class AgentRun:
    understanding: IncidentUnderstanding
    diagnosis: Diagnosis
    records: list[ToolCallRecord]
    budget: ToolBudget
    model: str | None
    agent_completed: bool
    events: list[str] = field(default_factory=list)


PROVIDER_FAILURES: tuple[tuple[type[BaseException], str], ...] = (
    (openai.APITimeoutError, "timeout: the model request timed out"),
    (openai.AuthenticationError, "http: the model provider rejected the credentials"),
    (openai.PermissionDeniedError, "http: the model provider denied access to the model"),
    (openai.RateLimitError, "http: the model provider rate limit was reached"),
    (openai.NotFoundError, "http: the configured model was not found"),
    (openai.APIConnectionError, "connection: the model provider could not be reached"),
    (openai.APIStatusError, "http: the model provider returned an error status"),
    (openai.APIError, "malformed: the model provider returned an unusable response"),
    (AgentFrameworkException, "malformed: the agent framework could not complete the run"),
)


def causes(exc: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and current not in chain and len(chain) < 10:
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def failure_message(exc: BaseException) -> str:
    chain = causes(exc)
    detail = next((text for kind, text in PROVIDER_FAILURES for cause in chain if isinstance(cause, kind)),
                  "malformed: the agent run failed unexpectedly")
    return f"Model provider error ({detail})"


class DiagnosisAgent:
    def __init__(self, settings: Settings | None = None, retriever: Retriever | None = None, http_client: Any = None,
                 rule_based: bool = False) -> None:
        self.settings = settings or get_settings()
        self.retriever = retriever or KnowledgeService().diagnosis_retriever()
        self.http_client = http_client
        self.model: AgentModel | None = None if rule_based else agent_model(self.settings)

    def opening(self, request: DiagnosisRequest, context, executor: ToolExecutor, understanding: IncidentUnderstanding) -> str:
        message = json.loads(ModelSession(self.model, executor, request, context, []).opening())
        message["task"] = ("Understand the incident, plan the diagnostic checks, call the tools one at a time, then reply with "
                           "the final JSON diagnosis.")
        message["incident_understanding"] = understanding.model_dump()
        message["tool_budget_rule"] = (f"At most {MAX_TOOL_CALLS} tool calls in total, shared by the diagnostic tools and "
                                       f"{KNOWLEDGE_TOOL} (at most {MAX_KNOWLEDGE_CALLS} searches). Identical calls are rejected.")
        return json.dumps(message)

    async def converse(self, budget: ToolBudget, opening: str, limitations: list[str], issues: list[str]) -> DiagnosisDraft | None:
        agent = build_agent(self.model, budget, self.http_client)
        try:
            response = await asyncio.wait_for(agent.run(opening), timeout=run_deadline(self.model.config))
        except asyncio.TimeoutError:
            limitations.append(f"Model provider error (timeout: the agent run exceeded {run_deadline(self.model.config):.0f} seconds)")
            return None
        except Exception as exc:
            limitations.append(failure_message(exc))
            return None
        draft = parse_draft(response.text)
        if draft is None:
            issues.append("Model output was not a valid diagnosis JSON object and was rejected")
        return draft

    async def arun(self, scenario_id: str, report: str, site_ids: Sequence[str] = (), device_ids: Sequence[str] = (),
                   services: Sequence[PathService] = (), incident_id: str | None = None, observer: Any = None,
                   cancel_event: Any = None) -> AgentRun:
        if scenario_id not in list_scenario_ids():
            raise DiagnosisRequestError(f"Unknown scenario '{scenario_id}'")
        if not report or not report.strip() or len(report) > MAX_REPORT_CHARS:
            raise DiagnosisRequestError(f"The incident report must contain 1 to {MAX_REPORT_CHARS} characters")
        topology = load_topology()
        understanding = understand(report, scenario_id, topology, site_ids, device_ids, services)
        request = DiagnosisRequest(scenario_id=scenario_id, description=redact(report), incident_id=incident_id,
                                   site_ids=understanding.sites[:5])
        context = resolve_context(request, topology)
        executor = ToolExecutor(scenario_id, observer=observer, cancel_event=cancel_event)
        budget = ToolBudget(executor, self.retriever if self.model else NoRetrieval())
        budget.observer = observer
        engine = DiagnosisEngine(self.model)
        flags = injection_flags("incident description", report)
        limitations: list[str] = [] if context.sites else ["No affected site could be identified from the incident report"]
        issues: list[str] = []
        events = [f"Understood incident: sites={understanding.sites or UNKNOWN}, services={understanding.services or UNKNOWN}, "
                  f"timeframe={understanding.timeframe}"]
        draft = None
        if self.model is not None:
            events.append(f"Agent started with model {self.model.model} and a budget of {budget.limit} tool calls")
            draft = await self.converse(budget, self.opening(request, context, executor, understanding), limitations, issues)
        validated, rejected = engine.validate(draft, executor, topology, context, issues)
        agent_completed = validated is not None
        if not agent_completed and context.sites and budget.remaining:
            executed = len(executor.executed)
            executor.max_calls = executed + budget.remaining

            def sufficient() -> bool:
                return correlate(executor.records, build_catalog(executor.records), topology, context.sites).confidence == Confidence.HIGH
            RuleBasedPlanner(topology, context).run(executor, sufficient)
            budget.attempts += len(executor.executed) - executed
            events.append(f"Rule-based planner collected evidence with {len(executor.executed) - executed} tool calls")
        events.append(f"Tool sequence: {', '.join(f'{r.call_id}:{r.tool}:{r.status}' for r in executor.records) or 'none'}")
        if budget.documents:
            events.append(f"Consulted guidance (unverified): {', '.join(sorted(budget.documents))}")
        diagnosis = engine.conclude(request, context, topology, executor, list(budget.documents.values()), flags + budget.flags,
                                    validated, rejected and self.model is not None, limitations, issues + budget.issues)
        return AgentRun(understanding=understanding, diagnosis=diagnosis, records=list(executor.records), budget=budget,
                        model=self.model.model if self.model else None, agent_completed=agent_completed, events=events)

    def run(self, scenario_id: str, report: str) -> AgentRun:
        return asyncio.run(self.arun(scenario_id, report))
