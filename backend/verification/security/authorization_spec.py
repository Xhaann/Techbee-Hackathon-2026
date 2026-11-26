from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.engine.schema import FaultDomain
from app.incidents import IncidentService, JsonIncidentRepository, LifecycleStatus, UnauthorizedActionError
from app.incidents.models import Actor
from app.security.permissions import (
    HUMAN_ONLY,
    ROLE_PERMISSIONS,
    AuthenticationError,
    AuthorizationError,
    Permission,
    Principal,
    Role,
    SecuredIncidentService,
    TokenAuthenticator,
    TokenRecord,
    authorize,
    hash_token,
)
from verification.incidents.helpers import SteppingClock, scenario_request

MANAGER = Principal(subject="lead", kind="human", roles=["incident_manager"])
OPERATOR = Principal(subject="noc", kind="human", roles=["operator"])
VIEWER = Principal(subject="auditor", kind="human", roles=["viewer"])
SYSTEM = Principal(subject="engine", kind="system", roles=["system_service"])
AI = Principal(subject="assistant", kind="ai", roles=["ai_assistant"])
TOKEN = "t" * 40


@pytest.fixture
def secured(tmp_path) -> SecuredIncidentService:
    return SecuredIncidentService(IncidentService(JsonIncidentRepository(tmp_path / "store"), SteppingClock()))


@pytest.mark.parametrize("kind, role", [("ai", "incident_manager"), ("ai", "operator"), ("system", "incident_manager"),
                                        ("system", "knowledge_manager"), ("human", "ai_assistant"), ("human", "system_service")])
def test_principals_cannot_hold_roles_of_other_actor_kinds(kind: str, role: str) -> None:
    with pytest.raises(ValidationError):
        Principal(subject="x", kind=kind, roles=[role])


def test_role_matrix_keeps_human_only_permissions_human() -> None:
    for role in (Role.SYSTEM_SERVICE, Role.AI_ASSISTANT):
        assert not ROLE_PERMISSIONS[role] & HUMAN_ONLY
    assert HUMAN_ONLY <= ROLE_PERMISSIONS[Role.INCIDENT_MANAGER] | ROLE_PERMISSIONS[Role.KNOWLEDGE_MANAGER]
    assert Permission.MANAGE_KNOWLEDGE not in ROLE_PERMISSIONS[Role.INCIDENT_MANAGER]


def test_missing_and_unauthenticated_principals() -> None:
    for principal in (None, "lead", {"subject": "lead"}, MANAGER.model_copy(update={"authenticated": False})):
        with pytest.raises(AuthenticationError):
            authorize(principal, Permission.VIEW_INCIDENTS)


def test_insufficient_permission() -> None:
    with pytest.raises(AuthorizationError):
        authorize(VIEWER, Permission.CREATE_INCIDENTS)
    with pytest.raises(AuthorizationError):
        authorize(OPERATOR, Permission.VERIFY_RESOLUTIONS)
    forged = Principal.model_construct(subject="assistant", kind="ai", roles=[Role.INCIDENT_MANAGER], authenticated=True)
    with pytest.raises(AuthorizationError, match="requires a human principal"):
        authorize(forged, Permission.CLOSE_REOPEN_INCIDENTS)
    assert authorize(MANAGER, Permission.VERIFY_RESOLUTIONS) is MANAGER


def test_token_authentication() -> None:
    now = datetime(2026, 3, 3, 10, tzinfo=timezone.utc)
    records = [TokenRecord(token_hash=hash_token(TOKEN), principal=MANAGER, expires_at=now + timedelta(hours=1)),
               TokenRecord(token_hash=hash_token("e" * 40), principal=OPERATOR, expires_at=now - timedelta(seconds=1))]
    authenticator = TokenAuthenticator(records, clock=lambda: now)
    assert authenticator.authenticate(TOKEN) == MANAGER
    for token, message in ((None, "required"), ("", "required"), ("short", "Invalid"), ("x" * 40, "Invalid"),
                           ("e" * 40, "expired"), ("t" * 300, "Invalid"), (12345, "required")):
        with pytest.raises(AuthenticationError, match=message) as error:
            authenticator.authenticate(token)
        assert error.value.status_code == 401 and (not isinstance(token, str) or not token or token not in error.value.message)
    assert all(TOKEN not in record.model_dump_json() for record in records)
    with pytest.raises(ValueError):
        TokenAuthenticator(records + [records[0]])


def test_secured_service_enforces_permissions(secured: SecuredIncidentService) -> None:
    request = scenario_request("WAN-FAILURE")
    with pytest.raises(AuthorizationError):
        secured.create_incident(VIEWER, request)
    with pytest.raises(AuthenticationError):
        secured.create_incident(None, request)
    incident = secured.create_incident(OPERATOR, request).incident
    assert incident.timeline[0].actor == Actor(kind="human", actor_id="noc")
    assert secured.get_incident(VIEWER, incident.incident_id).incident_id == incident.incident_id
    secured.change_status(OPERATOR, incident.incident_id, LifecycleStatus.ACKNOWLEDGED)
    diagnosed = secured.run_diagnosis(SYSTEM, incident.incident_id)
    assert diagnosed.status == LifecycleStatus.DIAGNOSED and diagnosed.timeline[-1].actor.kind.value == "system"
    for principal, operation, args in ((AI, "classify", (FaultDomain.WAN_ISP, "x")), (SYSTEM, "close_incident", ("x",)),
                                       (SYSTEM, "verify_resolution", (True, "x")), (OPERATOR, "change_severity", ("low", "x")),
                                       (AI, "run_diagnosis", ()), (VIEWER, "update_details", ())):
        with pytest.raises(AuthorizationError):
            getattr(secured, operation)(principal, incident.incident_id, *args)
    assert secured.get_incident(MANAGER, incident.incident_id).version == diagnosed.version


def test_authorized_human_lifecycle_and_ai_proposal(secured: SecuredIncidentService) -> None:
    incident = secured.create_incident(OPERATOR, scenario_request("WAN-FAILURE")).incident
    secured.change_status(OPERATOR, incident.incident_id, LifecycleStatus.ACKNOWLEDGED)
    secured.run_diagnosis(SYSTEM, incident.incident_id)
    secured.change_status(OPERATOR, incident.incident_id, LifecycleStatus.MONITORING)
    secured.propose_resolution(AI, incident.incident_id, "Carrier restored the circuit", FaultDomain.WAN_ISP)
    with pytest.raises(AuthorizationError):
        secured.verify_resolution(AI, incident.incident_id, True, "auto")
    resolved = secured.verify_resolution(MANAGER, incident.incident_id, True, "Users confirmed")
    assert resolved.status == LifecycleStatus.RESOLVED and resolved.current_resolution.verified_by.actor_id == "lead"
    closed = secured.close_incident(MANAGER, incident.incident_id, "Monitoring complete")
    assert closed.status == LifecycleStatus.CLOSED


def test_phase5_kind_checks_still_apply_beneath_the_facade(tmp_path) -> None:
    service = IncidentService(JsonIncidentRepository(tmp_path / "s"), SteppingClock())
    incident = service.create_incident(scenario_request("WAN-FAILURE"), Actor(kind="human", actor_id="noc")).incident
    with pytest.raises(UnauthorizedActionError):
        service.classify(incident.incident_id, Actor(kind="ai", actor_id="assistant"), FaultDomain.WAN_ISP, "x")


def test_unknown_operations_are_rejected(secured: SecuredIncidentService) -> None:
    with pytest.raises(AuthorizationError):
        secured.call("delete_everything", MANAGER)
    with pytest.raises(AttributeError):
        secured.repository_internals


def test_secured_escalation_update_passes_the_authorized_human_actor(secured: SecuredIncidentService) -> None:
    from app.incidents.models import EscalationStatus
    incident = secured.create_incident(OPERATOR, scenario_request("WAN-FAILURE")).incident
    secured.change_status(OPERATOR, incident.incident_id, LifecycleStatus.ACKNOWLEDGED)
    secured.run_diagnosis(SYSTEM, incident.incident_id)
    escalation_id = secured.create_escalation(OPERATOR, incident.incident_id).escalations[0].escalation_id
    for principal in (VIEWER, OPERATOR, SYSTEM, AI):
        with pytest.raises(AuthorizationError):
            secured.update_escalation(principal, incident.incident_id, escalation_id, EscalationStatus.CANCELLED, "x")
    updated = secured.update_escalation(MANAGER, incident.incident_id, escalation_id, EscalationStatus.ASSIGNED, "Ticket opened",
                                        assigned_team="Carrier B NOC")
    assert updated.escalations[0].status == EscalationStatus.ASSIGNED
    assert updated.timeline[-1].event_type.value == "escalation_updated" and updated.timeline[-1].actor == Actor(kind="human", actor_id="lead")
