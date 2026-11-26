from fastapi import APIRouter

from app.api.dependencies import CurrentPrincipal, PageDependency, ServicesDependency
from app.api.records import all_incidents
from app.api.reporting import diagnosis_report, fault_domain_report, incident_counts, report_row
from app.api.schemas import CountSummary, IncidentReportRow, Page
from app.incidents.models import IncidentSummary

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/summary", response_model=CountSummary)
def summary(principal: CurrentPrincipal, registry: ServicesDependency) -> CountSummary:
    incidents = all_incidents(registry.secured_incidents, principal)
    result = incident_counts([IncidentSummary.of(incident) for incident in incidents])
    result.counts["records"] = {"diagnoses": sum(len(i.diagnoses) for i in incidents),
                                "escalations": sum(len(i.escalations) for i in incidents),
                                "resolutions": sum(len(i.resolutions) for i in incidents)}
    return result


@router.get("/incidents", response_model=Page[IncidentReportRow])
def incidents(principal: CurrentPrincipal, registry: ServicesDependency, page: PageDependency) -> dict:
    return page.slice([report_row(incident) for incident in all_incidents(registry.secured_incidents, principal)])


@router.get("/fault-domains", response_model=CountSummary)
def fault_domains(principal: CurrentPrincipal, registry: ServicesDependency) -> CountSummary:
    return fault_domain_report(all_incidents(registry.secured_incidents, principal))


@router.get("/diagnosis", response_model=CountSummary)
def diagnoses(principal: CurrentPrincipal, registry: ServicesDependency) -> CountSummary:
    return diagnosis_report(all_incidents(registry.secured_incidents, principal))
