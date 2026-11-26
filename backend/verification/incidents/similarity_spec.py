from datetime import timedelta

from app.engine.schema import FaultDomain
from app.incidents import IncidentFilter, IncidentService, LifecycleStatus
from app.incidents.models import IncidentSeverity
from app.incidents.similarity import CAUTION, MatchStrength
from verification.incidents.helpers import HUMAN, SECOND_HUMAN, create, diagnosed, resolved, scenario_request


def test_duplicate_report_is_linked_not_created(service: IncidentService) -> None:
    original = create(service)
    outcome = service.create_incident(scenario_request("WAN-FAILURE", title="Singapore office cannot reach any service"), HUMAN)
    assert outcome.created is False and outcome.incident.incident_id == original.incident_id
    assert "Same site (SIN)" in outcome.duplicate_reason and outcome.duplicate_of.caution == CAUTION
    assert outcome.incident.timeline[-1].event_type.value == "related_report_linked"
    assert len(service.list_incidents()) == 1


def test_forced_new_incident_is_created_and_flagged(service: IncidentService) -> None:
    original = create(service)
    outcome = service.create_incident(scenario_request("WAN-FAILURE", force_new=True), HUMAN)
    assert outcome.created and [m.incident_id for m in outcome.possible_duplicates] == [original.incident_id]
    assert original.incident_id in outcome.incident.timeline[0].details["possibly_related"]


def test_different_symptoms_at_same_site_are_not_merged(service: IncidentService) -> None:
    create(service)
    outcome = service.create_incident(scenario_request("WAN-FAILURE", title="Singapore printer jammed",
                                                       description="The third floor printer shows paper jam errors."), HUMAN)
    assert outcome.created and outcome.duplicate_of is None


def test_different_site_is_not_a_duplicate(service: IncidentService) -> None:
    create(service)
    outcome = service.create_incident(scenario_request("WAN-FAILURE", site_ids=["BLR"]), HUMAN)
    assert outcome.created and outcome.duplicate_of is None


def test_resolved_incidents_are_not_duplicate_targets(service: IncidentService) -> None:
    resolved(service)
    assert service.create_incident(scenario_request("WAN-FAILURE"), HUMAN).created


def test_similarity_explains_matches_and_differences(service: IncidentService) -> None:
    first = diagnosed(service, "WAN-FAILURE")
    second = diagnosed(service, "SHARED-DEVICE-FAILURE")
    matches = service.find_similar(second.incident_id)
    match = next(m for m in matches if m.incident_id == first.incident_id)
    assert match.matching["sites"] == ["SIN"] and match.matching["links"] == ["LNK-WAN-SIN"]
    assert "CORE-RTR-01" in match.differences["devices"]
    assert match.differences["fault_domain"] == ["shared_infrastructure", "wan_isp"]
    assert 0 < match.points < match.max_points and match.strength in set(MatchStrength)
    assert "does not establish a common root cause" in match.caution


def test_same_domain_different_site_and_path(service: IncidentService) -> None:
    wan = diagnosed(service, "WAN-FAILURE")
    loss = diagnosed(service, "PACKET-LOSS")
    match = next(m for m in service.find_similar(wan.incident_id) if m.incident_id == loss.incident_id)
    assert match.matching["fault_domain"] == ["wan_isp"]
    assert "sites" not in match.matching and set(match.differences["sites"]) == {"NYC", "SIN"}


def test_time_window_affects_similarity(service: IncidentService, clock) -> None:
    first = diagnosed(service, "WAN-FAILURE")
    clock.current += timedelta(days=3)
    second = diagnosed(service, "WAN-FAILURE", force_new=True)
    match = next(m for m in service.find_similar(second.incident_id) if m.incident_id == first.incident_id)
    assert "time_window" in match.differences and "time_window" not in match.matching
    wide = next(m for m in service.find_similar(second.incident_id, window=timedelta(days=7)) if m.incident_id == first.incident_id)
    assert "time_window" in wide.matching and wide.points > match.points


def test_historical_resolution_is_reported(service: IncidentService) -> None:
    old = resolved(service)
    new = diagnosed(service, "WAN-FAILURE", force_new=True)
    match = next(m for m in service.find_similar(new.incident_id) if m.incident_id == old.incident_id)
    assert match.historical_resolution == "Carrier restored the circuit"


def test_history_filters(service: IncidentService, clock) -> None:
    wan = diagnosed(service, "WAN-FAILURE")
    dns = create(service, "DNS-RESOLUTION-FAILURE", severity="critical")
    clock.current += timedelta(days=2)
    loss = diagnosed(service, "PACKET-LOSS")
    ids = lambda **kw: [s.incident_id for s in service.list_incidents(IncidentFilter(**kw))]
    assert ids(site_id="SIN") == [dns.incident_id, wan.incident_id]
    assert ids(site_id="BLR") == [dns.incident_id]
    assert ids(device_id="NYC-RTR-01") == [loss.incident_id]
    assert ids(severity=IncidentSeverity.CRITICAL) == [dns.incident_id]
    assert ids(status=LifecycleStatus.NEW) == [dns.incident_id]
    assert ids(fault_domain=FaultDomain.WAN_ISP) == [loss.incident_id, wan.incident_id]
    assert ids(end=clock.current - timedelta(days=1)) == [dns.incident_id, wan.incident_id]
    assert ids(limit=1) == [loss.incident_id]
    assert ids(site_id="BLR", status=LifecycleStatus.CLOSED) == []


def test_recurring_incidents_and_resolution_history(service: IncidentService, clock) -> None:
    first = resolved(service)
    clock.current += timedelta(days=5)
    second = diagnosed(service, "WAN-FAILURE", force_new=True)
    diagnosed(service, "PACKET-LOSS")
    groups = service.recurring_incidents()
    assert [(g.site_id, g.fault_domain, g.incident_ids) for g in groups] == [
        ("SIN", FaultDomain.WAN_ISP, [first.incident_id, second.incident_id])]
    assert "SIN-RTR-01" in groups[0].common_devices
    assert service.recurring_incidents(window=timedelta(days=1)) == []
    history = service.resolution_history()
    assert [(h.incident_id, h.resolution.verification.value) for h in history] == [(first.incident_id, "verified")]
    assert history[0].resolution.verified_by == SECOND_HUMAN
