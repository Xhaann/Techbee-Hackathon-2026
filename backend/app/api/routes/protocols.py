"""Phase 3 protocol and security intelligence API.

GET  /protocols/engines   the 17 engines and the synthetic protocol scenarios (anyone who may view diagnostics)
POST /protocols/analyze   runs the selected engines (all read-only, on synthetic telemetry) and returns the correlated
                          report; needs RUN_DIAGNOSTICS. With an incident, the incident must be visible to the caller and only
                          incidents the caller may see are used for correlation.
Nothing here contacts a device, scans a network or changes configuration.
"""
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from app.api.dependencies import CurrentPrincipal, ServicesDependency, not_found
from app.core.exceptions import AppError
from app.incidents.models import IncidentFilter
from app.network.models import Identifier
from app.network.repository import list_protocol_scenario_ids, load_scenario, load_topology, scenario_exists
from app.protocols.analysis import ProtocolReport, analyze
from app.protocols.registry import ENGINES, EngineName
from app.protocols.scenarios import SPEC_BY_ID
from app.security.permissions import Permission, authorize

router = APIRouter(prefix="/protocols", tags=["protocols"])


class ProtocolEngineInfo(BaseModel):
    name: str
    feature: int
    title: str
    specialist: str
    category: Literal["protocol", "security"]
    checks: str


class ProtocolScenario(BaseModel):
    scenario_id: str
    name: str
    description: str
    kind: Literal["normal", "failure", "edge", "adversarial"]
    features: list[str]
    incident_title: str | None = None
    site_ids: list[str] = Field(default_factory=list)


class ProtocolEngineCatalog(BaseModel):
    synthetic: Literal[True] = True
    engines: list[ProtocolEngineInfo]
    scenarios: list[ProtocolScenario]


class ProtocolAnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_id: Identifier | None = None
    incident_id: Identifier | None = None
    engines: list[EngineName] = Field(default_factory=list, max_length=17)
    site_id: Identifier | None = None
    device_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Z0-9]+(?:-[A-Z0-9]+)+$")
    symptoms: str = Field(default="", max_length=1000)


@router.get("/engines", response_model=ProtocolEngineCatalog)
def engines(principal: CurrentPrincipal) -> ProtocolEngineCatalog:
    authorize(principal, Permission.VIEW_DIAGNOSTICS)
    scenarios = []
    for scenario_id in list_protocol_scenario_ids():
        spec = SPEC_BY_ID.get(scenario_id)
        dataset = load_scenario(scenario_id)
        scenarios.append(ProtocolScenario(
            scenario_id=scenario_id, name=dataset.scenario.name, description=dataset.scenario.description, kind=spec.kind if spec else "failure",
            features=list(spec.features) if spec else [], incident_title=dataset.incident.title if dataset.incident else None,
            site_ids=dataset.incident.affected_site_ids if dataset.incident else []))
    return ProtocolEngineCatalog(engines=[ProtocolEngineInfo(name=e.name, feature=e.feature, title=e.title, specialist=e.specialist, category=e.category,
                                             checks=e.summary) for e in ENGINES], scenarios=scenarios)


@router.post("/analyze", response_model=ProtocolReport)
async def run(request: ProtocolAnalyzeRequest, principal: CurrentPrincipal, registry: ServicesDependency) -> ProtocolReport:
    """Runs the selected engines (or all 17). Read-only: the request is the user's explicit approval to run these checks."""
    authorize(principal, Permission.RUN_DIAGNOSTICS)
    if (request.scenario_id is None) == (request.incident_id is None):
        raise AppError("Give exactly one of scenario_id or incident_id", code="VALIDATION_ERROR", status_code=422)
    current = others = None
    symptoms = request.symptoms
    scenario_id = request.scenario_id
    if request.incident_id:
        incident = await run_in_threadpool(registry.secured_incidents.get_incident, principal, request.incident_id)
        if not incident.dataset_scenario_id:
            raise not_found("This incident has no telemetry dataset to analyse")
        scenario_id = incident.dataset_scenario_id
        symptoms = " ".join([symptoms, incident.title, incident.description, *incident.symptoms]).strip()
        current = {"incident_id": incident.incident_id, "site_ids": incident.site_ids, "created_at": incident.created_at, "devices": []}
        summaries = await run_in_threadpool(registry.secured_incidents.list_incidents, principal, IncidentFilter(limit=50))
        others = [{"incident_id": i.incident_id, "title": i.title, "site_ids": i.site_ids, "created_at": i.created_at, "devices": i.device_ids}
                  for i in summaries]
    if not scenario_exists(scenario_id):
        raise not_found(f"Unknown scenario '{scenario_id}'")
    topology = load_topology()
    if request.site_id and request.site_id not in {s.site_id for s in topology.sites}:
        raise not_found(f"Unknown site '{request.site_id}'")
    if request.device_id and request.device_id not in {d.device_id for d in topology.devices}:
        raise not_found(f"Unknown device '{request.device_id}'")
    names = list(dict.fromkeys(request.engines)) or [e.name for e in ENGINES]
    key = f"protocols|{principal.subject}|{scenario_id}|{','.join(sorted(names))}|{request.site_id}|{request.device_id}"
    with registry.in_flight.claim(key, "This protocol analysis is already running"):
        return await run_in_threadpool(analyze, scenario_id, names, request.site_id, request.device_id, symptoms, current, others)
