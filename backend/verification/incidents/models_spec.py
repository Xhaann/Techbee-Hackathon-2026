from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.incidents import IncidentCreateRequest, IncidentFilter, IncidentService, IncidentValidationError
from app.incidents.models import (
    TRANSITIONS,
    Actor,
    Incident,
    IncidentSeverity,
    LifecycleStatus,
    Resolution,
)
from verification.incidents.helpers import HUMAN, create, scenario_request


def test_valid_incident_creation(service: IncidentService) -> None:
    incident = create(service)
    assert incident.incident_id == "INC-20260303-0001" and incident.version == 1
    assert incident.status == LifecycleStatus.NEW and incident.source.value == "service_desk"
    assert incident.severity == IncidentSeverity.MEDIUM and incident.severity_source.value == "default"
    assert incident.priority.value == "p3" and incident.priority_source.value == "derived"
    assert incident.created_at.utcoffset().total_seconds() == 0
    assert [(a.asset_type.value, a.asset_id, a.basis.value) for a in incident.affected_assets] == [("site", "SIN", "reported")]
    assert len(incident.timeline) == 1 and incident.timeline[0].event_type.value == "created"


def test_explicit_severity_and_priority_are_preserved(service: IncidentService) -> None:
    incident = create(service, severity="critical", priority="p2")
    assert (incident.severity.value, incident.severity_source.value) == ("critical", "manual")
    assert (incident.priority.value, incident.priority_source.value) == ("p2", "manual")
    derived = create(service, "DNS-RESOLUTION-FAILURE", priority="p1")
    assert (derived.severity.value, derived.severity_source.value) == ("critical", "derived")


def test_identifiers_are_unique_and_sequential(service: IncidentService) -> None:
    ids = [create(service, scenario, force_new=True).incident_id
           for scenario in ("WAN-FAILURE", "PACKET-LOSS", "DNS-RESOLUTION-FAILURE")]
    assert ids == ["INC-20260303-0001", "INC-20260303-0002", "INC-20260303-0003"]


@pytest.mark.parametrize("overrides", [
    {"site_ids": ["MARS"]}, {"device_ids": ["GHOST-RTR-01"]}, {"dataset_scenario_id": "UNKNOWN"},
    {"reported_at": datetime(2030, 1, 1, tzinfo=timezone.utc)},
])
def test_invalid_references_are_rejected(service: IncidentService, overrides: dict) -> None:
    with pytest.raises(IncidentValidationError):
        service.create_incident(scenario_request("WAN-FAILURE", **overrides), HUMAN)


@pytest.mark.parametrize("overrides", [
    {"title": "x"}, {"description": ""}, {"site_ids": []}, {"site_ids": ["sin"]}, {"severity": "urgent"},
    {"priority": "p9"}, {"reported_at": "2026-03-03T09:00:00"}, {"reported_at": "2026-03-03T14:00:00+05:30"},
    {"source": "email"}, {"device_ids": ["../etc/passwd"]}, {"unexpected": True}, {"description": "x" * 5000},
])
def test_invalid_requests_fail_validation(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        scenario_request("WAN-FAILURE", **overrides)


def test_invalid_actor() -> None:
    for values in ({"kind": "robot", "actor_id": "x"}, {"kind": "human", "actor_id": "Bad Name"}, {"kind": "human", "actor_id": ""}):
        with pytest.raises(ValidationError):
            Actor(**values)


def test_incident_integrity_rules(service: IncidentService) -> None:
    data = create(service).model_dump(mode="json")
    event = data["timeline"][0]
    bad = [
        data | {"timeline": [event, event | {"sequence": 2}]},
        data | {"timeline": [event | {"event_id": "INC-20260303-0009-EV0001"}]},
        data | {"timeline": [event | {"event_type": "acknowledged"}]},
        data | {"status": "closed"},
        data | {"status": "resolved"},
        data | {"active_diagnosis_id": "DGN-20260303-0001-01"},
        data | {"evidence": [{"diagnosis_id": "DGN-20260303-0001-01", "evidence_id": "E1", "tool": "t", "code": "C"}]},
        data | {"status": "paused"},
        data | {"created_at": "2026-03-03T09:00:00"},
        data | {"affected_assets": data["affected_assets"] * 2},
        data | {"updated_at": "2026-03-01T00:00:00Z"},
    ]
    for payload in bad:
        with pytest.raises(ValidationError):
            Incident.model_validate(payload)


def test_resolution_requires_human_verifier() -> None:
    base = {"resolution_id": "RES-20260303-0001-01", "summary": "fixed", "fault_domain": "wan_isp",
            "proposed_by": HUMAN, "proposed_at": "2026-03-03T10:00:00Z"}
    assert Resolution(**base, verification="pending").verification.value == "pending"
    for values in ({"verification": "verified"},
                   {"verification": "verified", "verified_by": {"kind": "ai", "actor_id": "bot"},
                    "verified_at": "2026-03-03T10:05:00Z", "resolved_at": "2026-03-03T10:05:00Z"},
                   {"verification": "verified", "verified_by": HUMAN, "verified_at": "2026-03-03T10:05:00Z"}):
        with pytest.raises(ValidationError):
            Resolution(**base, **values)


def test_transition_table_is_explicit() -> None:
    assert set(TRANSITIONS) == set(LifecycleStatus)
    assert TRANSITIONS[LifecycleStatus.NEW] == {LifecycleStatus.ACKNOWLEDGED}
    assert LifecycleStatus.RESOLVED in TRANSITIONS[LifecycleStatus.MONITORING]
    assert all(LifecycleStatus.RESOLVED not in targets for status, targets in TRANSITIONS.items()
               if status != LifecycleStatus.MONITORING)


def test_filter_validation() -> None:
    with pytest.raises(ValidationError):
        IncidentFilter(start=datetime(2026, 3, 4, tzinfo=timezone.utc), end=datetime(2026, 3, 3, tzinfo=timezone.utc))
    for values in ({"limit": 0}, {"limit": 1000}, {"severity": "urgent"}, {"site_id": "../x"}):
        with pytest.raises(ValidationError):
            IncidentFilter(**values)
    assert IncidentCreateRequest.model_fields["force_new"].default is False
