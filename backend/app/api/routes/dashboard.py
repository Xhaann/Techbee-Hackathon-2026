from collections import Counter

from fastapi import APIRouter, Depends

from app.api.dependencies import CurrentPrincipal, PageDependency, ScenarioDependency, ServicesDependency, require, tool_data
from app.api.records import REPORT_LIMIT
from app.api.reporting import incident_counts
from app.api.schemas import CountSummary, DeviceHealth, NetworkHealth, Page
from app.diagnostics import check_device_availability
from app.incidents.models import IncidentFilter, IncidentSummary, LifecycleStatus
from app.network.repository import load_topology
from app.security.permissions import Permission

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
INACTIVE = {LifecycleStatus.CLOSED, LifecycleStatus.RESOLVED}


@router.get("/summary", response_model=CountSummary)
def summary(principal: CurrentPrincipal, registry: ServicesDependency) -> CountSummary:
    summaries = registry.secured_incidents.list_incidents(principal, IncidentFilter(limit=REPORT_LIMIT))
    return incident_counts(summaries)


@router.get("/incidents", response_model=Page[IncidentSummary])
def active_incidents(principal: CurrentPrincipal, registry: ServicesDependency, page: PageDependency) -> dict:
    summaries = registry.secured_incidents.list_incidents(principal, IncidentFilter(limit=REPORT_LIMIT))
    return page.slice([s for s in summaries if s.status not in INACTIVE])


@router.get("/network-health", response_model=NetworkHealth, dependencies=[Depends(require(Permission.VIEW_DIAGNOSTICS))])
def network_health(scenario_id: ScenarioDependency) -> NetworkHealth:
    devices = []
    for device in load_topology().devices:
        result = tool_data(check_device_availability(scenario_id, device.device_id))
        devices.append(DeviceHealth(device_id=device.device_id, site_id=device.site_id, status=result.data["status"],
                                    finding_codes=sorted({finding.code for finding in result.findings})))
    sites: dict[str, Counter] = {}
    for device in devices:
        sites.setdefault(device.site_id, Counter())[device.status] += 1
    return NetworkHealth(scenario_id=scenario_id, device_count=len(devices), status_counts=dict(Counter(d.status for d in devices)),
                         sites={site: dict(counts) for site, counts in sorted(sites.items())}, devices=devices)
