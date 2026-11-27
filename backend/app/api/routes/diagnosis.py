from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from app.api.dependencies import CurrentPrincipal, PageDependency, ServicesDependency, not_found
from app.api.records import DiagnosisPath, diagnosis_record, evidence_page
from app.api.schemas import EvidencePage
from app.advanced import AdvancedDiagnosis, AdvancedRequest
from app.engine.schema import Diagnosis, DiagnosisRequest
from app.incidents.models import DiagnosisRecord
from app.network.repository import scenario_exists
from app.network.models import Identifier
from app.network.repository import load_scenario
from app.reasoning.report import ReasoningReport, analyze
from app.reasoning.specialists import Scope, investigate
from app.security.permissions import Permission, SecuredIncidentService, authorize

router = APIRouter(prefix="/diagnosis", tags=["diagnosis"])


def known_scenario(scenario_id: str) -> None:
    if not scenario_exists(scenario_id):
        raise not_found(f"Unknown scenario '{scenario_id}'")


@router.post("", response_model=Diagnosis)
def diagnose(request: DiagnosisRequest, principal: CurrentPrincipal, registry: ServicesDependency) -> Diagnosis:
    authorize(principal, Permission.RUN_DIAGNOSTICS)
    known_scenario(request.scenario_id)
    with registry.model_slot():
        return registry.diagnosis_engine().diagnose(request)


@router.post("/advanced", response_model=AdvancedDiagnosis)
def advanced(request: AdvancedRequest, principal: CurrentPrincipal, registry: ServicesDependency) -> AdvancedDiagnosis:
    authorize(principal, Permission.RUN_DIAGNOSTICS)
    known_scenario(request.diagnosis.scenario_id)
    if request.incident_id:
        registry.secured_incidents.get_incident(principal, request.incident_id)
    else:
        authorize(principal, Permission.VIEW_INCIDENTS)
    with registry.model_slot():
        return registry.advanced_engine(SecuredIncidentService.visibility(principal)).analyze(request)


class MultiAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_id: Identifier
    site_ids: list[Identifier] = Field(min_length=1, max_length=5)
    services: list[Literal["application", "internet", "dns", "dhcp", "authentication"]] = Field(default_factory=list, max_length=5)
    unaffected_site_ids: list[Identifier] = Field(default_factory=list, max_length=5)
    description: str = Field(default="", max_length=2000)


class PlannedCheckView(BaseModel):
    agent: str
    tool: str
    arguments: dict
    reason: str
    executed: bool


class MultiAgentDiagnosis(BaseModel):
    scenario_id: str
    method: Literal["multi_agent_rule_based"] = "multi_agent_rule_based"
    plan: list[PlannedCheckView]
    tool_calls: int
    budget_limit: int
    evidence_count: int
    reasoning: ReasoningReport
    human_verification_required: Literal[True] = True


@router.post("/multi-agent", response_model=MultiAgentDiagnosis)
def multi_agent(request: MultiAgentRequest, principal: CurrentPrincipal, registry: ServicesDependency) -> MultiAgentDiagnosis:
    """Four deterministic specialist agents (transport, routing, security, DNS/DHCP) plan read-only checks under one shared
    budget, then the reasoning engine weighs the evidence. No model is called and nothing is changed."""
    authorize(principal, Permission.RUN_DIAGNOSTICS)
    known_scenario(request.scenario_id)
    scope = Scope(request.scenario_id, tuple(request.site_ids), tuple(request.services), (), tuple(request.unaffected_site_ids),
                  request.description)
    with registry.in_flight.claim(f"multi-agent|{principal.subject}|{scope}", "This investigation is already running"):
        run = investigate(scope)
    executed = {check.key for check in run.executed}
    report = analyze(run.evidence, scope, load_scenario(request.scenario_id).scenario.onset_at, run.executed)
    return MultiAgentDiagnosis(scenario_id=request.scenario_id,
                               plan=[PlannedCheckView(agent=c.agent, tool=c.tool, arguments=c.arguments, reason=c.reason,
                                                      executed=c.key in executed) for c in run.plan],
                               tool_calls=len(run.executed), budget_limit=10, evidence_count=len(run.evidence), reasoning=report)


@router.get("/{diagnosis_id}", response_model=DiagnosisRecord)
def get(diagnosis_id: DiagnosisPath, principal: CurrentPrincipal, registry: ServicesDependency) -> DiagnosisRecord:
    return diagnosis_record(registry.secured_incidents, principal, diagnosis_id)


@router.get("/{diagnosis_id}/evidence", response_model=EvidencePage)
def evidence(diagnosis_id: DiagnosisPath, principal: CurrentPrincipal, registry: ServicesDependency,
             page: PageDependency) -> EvidencePage:
    return evidence_page([diagnosis_record(registry.secured_incidents, principal, diagnosis_id)], page)
