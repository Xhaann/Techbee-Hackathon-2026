import pytest

from app.engine.schema import FaultDomain
from app.incidents import IncidentService, IncidentValidationError, InvalidTransitionError, UnauthorizedActionError
from app.incidents.models import EscalationStatus, IncidentSeverity, LifecycleStatus, VerificationStatus
from verification.incidents.helpers import AI, HUMAN, SECOND_HUMAN, SYSTEM, create, diagnosed, resolved


def test_full_lifecycle(service: IncidentService) -> None:
    incident = resolved(service)
    assert incident.status == LifecycleStatus.RESOLVED
    assert incident.current_resolution.verification == VerificationStatus.VERIFIED
    assert incident.classification.confirmed_fault_domain == FaultDomain.WAN_ISP
    closed = service.close_incident(incident.incident_id, HUMAN, "Monitoring period completed")
    assert closed.status == LifecycleStatus.CLOSED and closed.closure.closed_by == HUMAN
    events = [event.event_type.value for event in closed.timeline]
    assert events[:2] == ["created", "acknowledged"] and events[-1] == "closed"
    assert {"investigation_started", "diagnosis_completed", "monitoring_started", "resolution_proposed",
            "resolution_verified", "resolved"} <= set(events)


@pytest.mark.parametrize("target", [LifecycleStatus.INVESTIGATING, LifecycleStatus.DIAGNOSED, LifecycleStatus.MONITORING,
                                    LifecycleStatus.NEW])
def test_invalid_transitions_from_new(service: IncidentService, target: LifecycleStatus) -> None:
    incident = create(service)
    with pytest.raises(InvalidTransitionError):
        service.change_status(incident.incident_id, HUMAN, target)
    assert service.get_incident(incident.incident_id).version == 1


@pytest.mark.parametrize("target", [LifecycleStatus.ESCALATED, LifecycleStatus.RESOLVED, LifecycleStatus.CLOSED])
def test_dedicated_operations_are_required(service: IncidentService, target: LifecycleStatus) -> None:
    incident = diagnosed(service)
    with pytest.raises(InvalidTransitionError, match="Use "):
        service.change_status(incident.incident_id, HUMAN, target)


def test_diagnosed_requires_a_diagnosis(service: IncidentService) -> None:
    incident = create(service)
    service.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    service.change_status(incident.incident_id, HUMAN, LifecycleStatus.INVESTIGATING)
    with pytest.raises(InvalidTransitionError, match="without an associated diagnosis"):
        service.change_status(incident.incident_id, HUMAN, LifecycleStatus.DIAGNOSED)


def test_escalation_records_are_structured_and_not_sent(service: IncidentService) -> None:
    incident = service.create_escalation(diagnosed(service).incident_id, SYSTEM)
    escalation = incident.escalations[0]
    assert incident.status == LifecycleStatus.ESCALATED
    assert escalation.escalation_id == "ESC-20260303-0001-01" and escalation.status == EscalationStatus.RECOMMENDED
    assert escalation.delivery == "not_sent" and escalation.assigned_team is None
    assert escalation.recommended_team == "WAN Operations / carrier liaison"
    assert escalation.fault_domain == FaultDomain.WAN_ISP and escalation.evidence_ids
    assert escalation.outstanding_checks and "probable, unverified" in escalation.handover_summary
    assert "not sent" in incident.timeline[-1].description
    assigned = service.update_escalation(incident.incident_id, escalation.escalation_id, HUMAN, EscalationStatus.ASSIGNED,
                                         "Ticket raised with carrier", assigned_team="Carrier B NOC")
    assert assigned.escalations[0].assigned_team == "Carrier B NOC"
    with pytest.raises(InvalidTransitionError):
        service.update_escalation(incident.incident_id, escalation.escalation_id, HUMAN, EscalationStatus.RECOMMENDED, "back")
    with pytest.raises(UnauthorizedActionError):
        service.update_escalation(incident.incident_id, escalation.escalation_id, SYSTEM, EscalationStatus.CLOSED, "auto")


def test_escalation_without_diagnosis_needs_explicit_details(service: IncidentService) -> None:
    incident = create(service)
    with pytest.raises(InvalidTransitionError):
        service.create_escalation(incident.incident_id, HUMAN, team="WAN Operations", reason="Branch down")
    service.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    service.change_status(incident.incident_id, HUMAN, LifecycleStatus.INVESTIGATING)
    with pytest.raises(IncidentValidationError):
        service.create_escalation(incident.incident_id, HUMAN)
    escalated = service.create_escalation(incident.incident_id, HUMAN, team="WAN Operations", reason="Branch down")
    assert escalated.escalations[0].fault_domain == FaultDomain.UNKNOWN and escalated.escalations[0].diagnosis_id is None


def test_resolution_requires_human_verification(service: IncidentService) -> None:
    incident = diagnosed(service)
    service.change_status(incident.incident_id, HUMAN, LifecycleStatus.MONITORING)
    proposed = service.propose_resolution(incident.incident_id, AI, "Circuit restored", FaultDomain.WAN_ISP)
    assert proposed.status == LifecycleStatus.MONITORING
    assert proposed.current_resolution.verification == VerificationStatus.PENDING
    assert "awaiting human verification" in proposed.timeline[-1].description
    for actor in (AI, SYSTEM):
        with pytest.raises(UnauthorizedActionError):
            service.verify_resolution(incident.incident_id, actor, True, "auto")
    with pytest.raises(IncidentValidationError):
        service.propose_resolution(incident.incident_id, HUMAN, "Another", FaultDomain.WAN_ISP)
    rejected = service.verify_resolution(incident.incident_id, HUMAN, False, "Users still offline")
    assert rejected.status == LifecycleStatus.MONITORING
    assert rejected.current_resolution.verification == VerificationStatus.REJECTED
    assert rejected.classification.confirmed_fault_domain is None


def test_resolution_verification_requires_monitoring(service: IncidentService) -> None:
    incident = diagnosed(service)
    service.propose_resolution(incident.incident_id, HUMAN, "Circuit restored", FaultDomain.WAN_ISP)
    with pytest.raises(InvalidTransitionError, match="monitoring"):
        service.verify_resolution(incident.incident_id, HUMAN, True, "ok")
    assert service.get_incident(incident.incident_id).status == LifecycleStatus.DIAGNOSED


def test_closure_conditions(service: IncidentService) -> None:
    incident = diagnosed(service)
    with pytest.raises(InvalidTransitionError, match="must be resolved"):
        service.close_incident(incident.incident_id, HUMAN, "close")
    escalated = service.create_escalation(incident.incident_id, SYSTEM)
    service.change_status(incident.incident_id, HUMAN, LifecycleStatus.MONITORING)
    service.propose_resolution(incident.incident_id, HUMAN, "Restored", FaultDomain.WAN_ISP)
    service.verify_resolution(incident.incident_id, SECOND_HUMAN, True, "confirmed")
    with pytest.raises(InvalidTransitionError, match="open escalations"):
        service.close_incident(incident.incident_id, HUMAN, "close")
    service.update_escalation(incident.incident_id, escalated.escalations[0].escalation_id, HUMAN, EscalationStatus.CLOSED, "done")
    with pytest.raises(UnauthorizedActionError):
        service.close_incident(incident.incident_id, SYSTEM, "close")
    with pytest.raises(IncidentValidationError):
        service.close_incident(incident.incident_id, HUMAN, "  ")
    assert service.close_incident(incident.incident_id, HUMAN, "close").status == LifecycleStatus.CLOSED


def test_reopen_requires_reason_and_reverts_resolution(service: IncidentService) -> None:
    incident = resolved(service)
    with pytest.raises(IncidentValidationError):
        service.reopen_incident(incident.incident_id, HUMAN, "")
    with pytest.raises(UnauthorizedActionError):
        service.reopen_incident(incident.incident_id, AI, "AI thinks it broke")
    reopened = service.reopen_incident(incident.incident_id, HUMAN, "Circuit dropped again")
    assert reopened.status == LifecycleStatus.INVESTIGATING
    assert reopened.current_resolution.verification == VerificationStatus.REVERTED
    assert reopened.timeline[-1].event_type.value == "reopened" and "dropped again" in reopened.timeline[-1].description
    with pytest.raises(InvalidTransitionError):
        service.reopen_incident(incident.incident_id, HUMAN, "again")
    with pytest.raises(InvalidTransitionError):
        service.change_status(resolved_incident_id(service), HUMAN, LifecycleStatus.INVESTIGATING)


def resolved_incident_id(service: IncidentService) -> str:
    return resolved(service, "PACKET-LOSS").incident_id


def test_severity_changes_are_recorded_and_never_silently_downgraded(service: IncidentService) -> None:
    incident = create(service)
    raised = service.change_severity(incident.incident_id, HUMAN, IncidentSeverity.CRITICAL, "Executive office affected")
    assert raised.severity_source.value == "manual" and raised.priority.value == "p1"
    assert [e.event_type.value for e in raised.timeline[-2:]] == ["severity_changed", "priority_changed"]
    service.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    after = service.run_diagnosis(incident.incident_id, SYSTEM)
    assert after.severity == IncidentSeverity.CRITICAL
    lowered = service.change_severity(incident.incident_id, HUMAN, IncidentSeverity.LOW, "Only one user affected")
    assert lowered.severity == IncidentSeverity.LOW and "lowered" in lowered.timeline[-2].description
    with pytest.raises(UnauthorizedActionError):
        service.change_severity(incident.incident_id, SYSTEM, IncidentSeverity.HIGH, "auto")
    with pytest.raises(IncidentValidationError):
        service.change_severity(incident.incident_id, HUMAN, IncidentSeverity.HIGH, "")
    manual_priority = service.change_priority(incident.incident_id, HUMAN, "p2", "Business hours")
    assert manual_priority.priority_source.value == "manual"


def test_diagnosis_upgrades_default_severity_from_impact(service: IncidentService) -> None:
    incident = diagnosed(service)
    assert (incident.severity, incident.severity_source.value, incident.priority.value) == (IncidentSeverity.HIGH, "derived", "p2")
    assert any(e.event_type.value == "severity_changed" and e.details["source"] == "derived" for e in incident.timeline)


def test_classification_requires_human_confirmation(service: IncidentService) -> None:
    incident = diagnosed(service)
    assert incident.classification.probable_fault_domain == FaultDomain.WAN_ISP
    assert incident.classification.confirmed_fault_domain is None
    with pytest.raises(UnauthorizedActionError):
        service.classify(incident.incident_id, AI, FaultDomain.WAN_ISP, "model says so")
    confirmed = service.classify(incident.incident_id, HUMAN, FaultDomain.ROUTING, "Carrier reports no fault")
    assert confirmed.classification.confirmed_fault_domain == FaultDomain.ROUTING
    assert confirmed.classification.probable_fault_domain == FaultDomain.WAN_ISP
    event = confirmed.timeline[-1]
    assert event.event_type.value == "classification_changed" and event.details["probable"] == "wan_isp"
    with pytest.raises(IncidentValidationError):
        service.classify(incident.incident_id, HUMAN, FaultDomain.ROUTING, "again")


def test_details_update_and_assignment(service: IncidentService) -> None:
    incident = create(service)
    updated = service.update_details(incident.incident_id, HUMAN, assigned_team="WAN Operations", assigned_owner="j.doe")
    assert (updated.assigned_team, updated.assigned_owner) == ("WAN Operations", "j.doe")
    with pytest.raises(IncidentValidationError):
        service.update_details(incident.incident_id, HUMAN)
    with pytest.raises(UnauthorizedActionError):
        service.update_details(incident.incident_id, AI, title="Rewritten by AI")
