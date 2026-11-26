from datetime import timedelta

import pytest

from app.advanced import AdvancedDiagnosisEngine, AdvancedRequest
from app.advanced.history import compare_history
from app.advanced.schema import CAUSATION_NOTICE
from app.incidents import IncidentService, JsonIncidentRepository
from verification.advanced_diagnosis.helpers import KNOWLEDGE
from verification.engine.helpers import incident_request
from verification.incidents.helpers import SteppingClock, create, diagnosed, resolved


@pytest.fixture
def incidents(tmp_path) -> tuple[IncidentService, SteppingClock]:
    clock = SteppingClock()
    return IncidentService(JsonIncidentRepository(tmp_path / "store"), clock), clock


def test_no_history_behaviour(incidents) -> None:
    service, _ = incidents
    assert not compare_history(None, None).available
    incident = create(service, "WAN-FAILURE")
    result = compare_history(service, incident.incident_id)
    assert result.available and result.similar == [] and result.message == "No similar historical incidents"


def test_similar_and_recurring_incidents_with_resolution(incidents) -> None:
    service, clock = incidents
    old = resolved(service, "WAN-FAILURE")
    clock.current += timedelta(days=3)
    current = diagnosed(service, "WAN-FAILURE", force_new=True)
    result = compare_history(service, current.incident_id)
    match = next(m for m in result.similar if m.incident_id == old.incident_id)
    assert match.matching["fault_domain"] == ["wan_isp"] and "SIN-RTR-01" in match.matching["devices"]
    assert result.resolution_notes[old.incident_id] == "Carrier restored the circuit"
    assert result.recurring_site_domains == ["SIN:wan_isp"] and result.notice == CAUSATION_NOTICE


def test_different_fault_domains_and_shared_devices(incidents) -> None:
    service, _ = incidents
    wan = diagnosed(service, "WAN-FAILURE")
    shared = diagnosed(service, "SHARED-DEVICE-FAILURE")
    match = next(m for m in compare_history(service, shared.incident_id).similar if m.incident_id == wan.incident_id)
    assert set(match.differences["fault_domain"]) == {"wan_isp", "shared_infrastructure"}
    assert "LNK-WAN-SIN" in match.matching["links"]
    assert "does not establish a common root cause" in match.caution


def test_conflicting_resolutions_are_not_copied(incidents) -> None:
    service, clock = incidents
    old = resolved(service, "WAN-FAILURE")
    clock.current += timedelta(days=1)
    current = diagnosed(service, "WAN-FAILURE", force_new=True)
    engine = AdvancedDiagnosisEngine(knowledge=KNOWLEDGE, incidents=service)
    result = engine.analyze(AdvancedRequest(diagnosis=incident_request("WAN-FAILURE"), incident_id=current.incident_id))
    assert result.history.available and old.incident_id in result.history.resolution_notes
    assert service.get_incident(current.incident_id).classification.confirmed_fault_domain is None
    assert result.primary_fault.status.value == "suspected"
