from fastapi import APIRouter

from app.api.dependencies import CurrentPrincipal, PageDependency, ServicesDependency, not_found
from app.api.records import DiagnosisPath, diagnosis_record, evidence_page
from app.api.schemas import EvidencePage
from app.advanced import AdvancedDiagnosis, AdvancedRequest
from app.engine.schema import Diagnosis, DiagnosisRequest
from app.incidents.models import DiagnosisRecord
from app.network.repository import list_scenario_ids
from app.security.permissions import Permission, authorize

router = APIRouter(prefix="/diagnosis", tags=["diagnosis"])


def known_scenario(scenario_id: str) -> None:
    if scenario_id not in list_scenario_ids():
        raise not_found(f"Unknown scenario '{scenario_id}'")


@router.post("", response_model=Diagnosis)
def diagnose(request: DiagnosisRequest, principal: CurrentPrincipal, registry: ServicesDependency) -> Diagnosis:
    authorize(principal, Permission.RUN_DIAGNOSTICS)
    known_scenario(request.scenario_id)
    return registry.diagnosis_engine().diagnose(request)


@router.post("/advanced", response_model=AdvancedDiagnosis)
def advanced(request: AdvancedRequest, principal: CurrentPrincipal, registry: ServicesDependency) -> AdvancedDiagnosis:
    authorize(principal, Permission.RUN_DIAGNOSTICS)
    known_scenario(request.diagnosis.scenario_id)
    if request.incident_id:
        registry.secured_incidents.get_incident(principal, request.incident_id)
    else:
        authorize(principal, Permission.VIEW_INCIDENTS)
    return registry.advanced_engine().analyze(request)


@router.get("/{diagnosis_id}", response_model=DiagnosisRecord)
def get(diagnosis_id: DiagnosisPath, principal: CurrentPrincipal, registry: ServicesDependency) -> DiagnosisRecord:
    return diagnosis_record(registry.secured_incidents, principal, diagnosis_id)


@router.get("/{diagnosis_id}/evidence", response_model=EvidencePage)
def evidence(diagnosis_id: DiagnosisPath, principal: CurrentPrincipal, registry: ServicesDependency,
             page: PageDependency) -> EvidencePage:
    return evidence_page([diagnosis_record(registry.secured_incidents, principal, diagnosis_id)], page)
