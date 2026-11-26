from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Path, Query, Response, status

from app.api.dependencies import CurrentPrincipal, PageDependency, ServicesDependency, invalid, not_found
from app.api.records import IncidentPath, REPORT_LIMIT, current, evidence_page, expected
from app.api.schemas import (
    ClassificationRequest,
    CloseRequest,
    EscalationRequest,
    EscalationUpdateRequest,
    EscalationView,
    EvidencePage,
    IncidentPatch,
    Page,
    ReopenRequest,
    ResolutionRequest,
    VersionedRequest,
)
from app.engine.schema import FaultDomain
from app.incidents import Incident, IncidentCreateRequest, IncidentFilter, IncidentService
from app.incidents.models import DeviceId, IncidentSeverity, IncidentSummary, LifecycleStatus, TimelineEvent
from app.incidents.service import CreationOutcome
from app.network.models import Identifier
from app.security.permissions import Permission, authorize

router = APIRouter(prefix="/incidents", tags=["incidents"])
EscalationPath = Annotated[str, Path(pattern=r"^ESC-\d{8}-\d{4}-\d{2,4}$")]
DETAIL_FIELDS = ("title", "description", "assigned_team", "assigned_owner")


@router.post("", response_model=CreationOutcome, status_code=status.HTTP_201_CREATED)
def create(request: IncidentCreateRequest, principal: CurrentPrincipal, registry: ServicesDependency,
           response: Response) -> CreationOutcome:
    outcome = registry.secured_incidents.create_incident(principal, request)
    if not outcome.created:
        response.status_code = status.HTTP_200_OK
    return outcome


@router.get("", response_model=Page[IncidentSummary])
def list_incidents(principal: CurrentPrincipal, registry: ServicesDependency, page: PageDependency,
                   site_id: Identifier | None = None, device_id: DeviceId | None = None, severity: IncidentSeverity | None = None,
                   status_filter: Annotated[LifecycleStatus | None, Query(alias="status")] = None, fault_domain: FaultDomain | None = None,
                   start: datetime | None = None, end: datetime | None = None) -> dict:
    criteria = IncidentFilter(site_id=site_id, device_id=device_id, severity=severity, status=status_filter,
                              fault_domain=fault_domain, start=start, end=end, limit=REPORT_LIMIT)
    return page.slice(registry.secured_incidents.list_incidents(principal, criteria))


@router.get("/{incident_id}", response_model=Incident)
def get(incident_id: IncidentPath, principal: CurrentPrincipal, registry: ServicesDependency) -> Incident:
    return registry.secured_incidents.get_incident(principal, incident_id)


@router.patch("/{incident_id}", response_model=Incident)
def patch(incident_id: IncidentPath, change: IncidentPatch, principal: CurrentPrincipal, registry: ServicesDependency) -> Incident:
    secured = registry.secured_incidents
    supplied = change.model_fields_set - {"expected_version", "reason"}
    details = {name: getattr(change, name) for name in DETAIL_FIELDS if name in supplied}
    groups = [group for group in (details, supplied & {"severity"}, supplied & {"priority"}, supplied & {"status"}) if group]
    if len(groups) != 1:
        raise invalid("Supply exactly one change: incident details, severity, priority or status")
    with expected(secured, principal, incident_id, change.expected_version):
        if details:
            return secured.update_details(principal, incident_id, **details)
        if change.severity is not None:
            return secured.change_severity(principal, incident_id, change.severity, change.reason or "")
        if change.priority is not None:
            return secured.change_priority(principal, incident_id, change.priority, change.reason or "")
        if change.status is None:
            raise invalid("Status must not be null")
        return secured.change_status(principal, incident_id, change.status, change.reason)


@router.get("/{incident_id}/timeline", response_model=Page[TimelineEvent])
def timeline(incident_id: IncidentPath, principal: CurrentPrincipal, registry: ServicesDependency, page: PageDependency) -> dict:
    return page.slice(registry.secured_incidents.timeline(principal, incident_id))


@router.post("/{incident_id}/diagnosis", response_model=Incident)
def run_diagnosis(incident_id: IncidentPath, request: VersionedRequest, principal: CurrentPrincipal,
                  registry: ServicesDependency) -> Incident:
    secured = registry.secured_incidents
    authorize(principal, Permission.RUN_DIAGNOSTICS)
    incident = current(secured, principal, incident_id, request.expected_version)
    diagnosis = registry.diagnosis_engine().diagnose(IncidentService.diagnosis_request(incident))
    with expected(secured, principal, incident_id, request.expected_version):
        return secured.associate_diagnosis(principal, incident_id, diagnosis)


@router.post("/{incident_id}/classification", response_model=Incident)
def classify(incident_id: IncidentPath, request: ClassificationRequest, principal: CurrentPrincipal,
             registry: ServicesDependency) -> Incident:
    secured = registry.secured_incidents
    with expected(secured, principal, incident_id, request.expected_version):
        return secured.classify(principal, incident_id, request.fault_domain, request.reason)


@router.post("/{incident_id}/resolution", response_model=Incident)
def resolution(incident_id: IncidentPath, request: ResolutionRequest, principal: CurrentPrincipal,
               registry: ServicesDependency) -> Incident:
    secured = registry.secured_incidents
    if request.action == "propose":
        if request.summary is None or request.fault_domain is None or request.approved is not None or request.note is not None:
            raise invalid("A proposal requires summary and fault_domain and accepts notes and responsible_team")
        with expected(secured, principal, incident_id, request.expected_version):
            return secured.propose_resolution(principal, incident_id, request.summary, request.fault_domain, notes=request.notes,
                                              responsible_team=request.responsible_team)
    if request.approved is None or request.note is None or request.summary is not None or request.fault_domain is not None:
        raise invalid("A verification requires approved and note and accepts responsible_team")
    with expected(secured, principal, incident_id, request.expected_version):
        return secured.verify_resolution(principal, incident_id, request.approved, request.note,
                                         responsible_team=request.responsible_team)


@router.post("/{incident_id}/close", response_model=Incident)
def close(incident_id: IncidentPath, request: CloseRequest, principal: CurrentPrincipal, registry: ServicesDependency) -> Incident:
    secured = registry.secured_incidents
    with expected(secured, principal, incident_id, request.expected_version):
        return secured.close_incident(principal, incident_id, request.note)


@router.post("/{incident_id}/reopen", response_model=Incident)
def reopen(incident_id: IncidentPath, request: ReopenRequest, principal: CurrentPrincipal, registry: ServicesDependency) -> Incident:
    secured = registry.secured_incidents
    with expected(secured, principal, incident_id, request.expected_version):
        return secured.reopen_incident(principal, incident_id, request.reason)


@router.get("/{incident_id}/evidence", response_model=EvidencePage)
def evidence(incident_id: IncidentPath, principal: CurrentPrincipal, registry: ServicesDependency,
             page: PageDependency) -> EvidencePage:
    incident = registry.secured_incidents.get_incident(principal, incident_id)
    active = incident.active_diagnosis
    return evidence_page([active] if active else [], page)


@router.get("/{incident_id}/escalations", response_model=Page[EscalationView])
def escalations(incident_id: IncidentPath, principal: CurrentPrincipal, registry: ServicesDependency, page: PageDependency) -> dict:
    incident = registry.secured_incidents.get_incident(principal, incident_id)
    return page.slice([EscalationView(**record.model_dump()) for record in incident.escalations])


@router.post("/{incident_id}/escalations", response_model=EscalationView, status_code=status.HTTP_201_CREATED)
def escalate(incident_id: IncidentPath, request: EscalationRequest, principal: CurrentPrincipal,
             registry: ServicesDependency) -> EscalationView:
    secured = registry.secured_incidents
    with expected(secured, principal, incident_id, request.expected_version):
        incident = secured.create_escalation(principal, incident_id, team=request.team, priority=request.priority, reason=request.reason)
        return EscalationView(**incident.escalations[-1].model_dump())


@router.patch("/{incident_id}/escalations/{escalation_id}", response_model=EscalationView)
def update_escalation(incident_id: IncidentPath, escalation_id: EscalationPath, request: EscalationUpdateRequest,
                      principal: CurrentPrincipal, registry: ServicesDependency) -> EscalationView:
    secured = registry.secured_incidents
    authorize(principal, Permission.UPDATE_ESCALATIONS)
    with expected(secured, principal, incident_id, request.expected_version) as incident:
        if all(record.escalation_id != escalation_id for record in incident.escalations):
            raise not_found(f"Unknown escalation '{escalation_id}'")
        updated = secured.update_escalation(principal, incident_id, escalation_id, request.status, request.note,
                                            assigned_team=request.assigned_team)
        return EscalationView(**next(e for e in updated.escalations if e.escalation_id == escalation_id).model_dump())
