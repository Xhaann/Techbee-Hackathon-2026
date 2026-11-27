import hashlib
import hmac
from collections.abc import Callable
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.exceptions import AppError
from app.incidents.errors import IncidentNotFoundError
from app.incidents.models import Actor, ActorKind, Incident
from app.incidents.service import IncidentService
from app.network.models import UtcDatetime

MIN_TOKEN_LENGTH = 32
MAX_TOKEN_LENGTH = 256
TOKEN_HASH = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class AuthenticationError(AppError):
    def __init__(self, message: str = "Authentication is required") -> None:
        super().__init__(message, code="AUTHENTICATION_REQUIRED", status_code=401)


class AuthorizationError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="PERMISSION_DENIED", status_code=403)


class Permission(str, Enum):
    VIEW_DIAGNOSTICS = "view_diagnostics"
    RUN_DIAGNOSTICS = "run_diagnostics"
    VIEW_INCIDENTS = "view_incidents"
    VIEW_ALL_INCIDENTS = "view_all_incidents"
    CREATE_INCIDENTS = "create_incidents"
    UPDATE_INCIDENTS = "update_incidents"
    PROPOSE_RESOLUTIONS = "propose_resolutions"
    CONFIRM_CLASSIFICATION = "confirm_classification"
    CHANGE_SEVERITY_PRIORITY = "change_severity_priority"
    VERIFY_RESOLUTIONS = "verify_resolutions"
    CLOSE_REOPEN_INCIDENTS = "close_reopen_incidents"
    UPDATE_ESCALATIONS = "update_escalations"
    MANAGE_KNOWLEDGE = "manage_knowledge"
    INGEST_TELEMETRY = "ingest_telemetry"


HUMAN_ONLY = frozenset({
    Permission.CONFIRM_CLASSIFICATION, Permission.CHANGE_SEVERITY_PRIORITY, Permission.VERIFY_RESOLUTIONS,
    Permission.CLOSE_REOPEN_INCIDENTS, Permission.UPDATE_ESCALATIONS, Permission.MANAGE_KNOWLEDGE,
})


class Role(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    INCIDENT_MANAGER = "incident_manager"
    KNOWLEDGE_MANAGER = "knowledge_manager"
    SYSTEM_SERVICE = "system_service"
    AI_ASSISTANT = "ai_assistant"


VIEW = {Permission.VIEW_DIAGNOSTICS, Permission.VIEW_INCIDENTS}
# Operators see and act on the incidents they reported or own. Team scope (every incident) is an explicit permission:
# incident managers supervise the queue, viewers and knowledge managers read it, and service accounts act for the team.
TEAM = {Permission.VIEW_ALL_INCIDENTS}
OPERATE = VIEW | {Permission.RUN_DIAGNOSTICS, Permission.CREATE_INCIDENTS, Permission.UPDATE_INCIDENTS, Permission.PROPOSE_RESOLUTIONS}
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset(VIEW | TEAM),
    Role.OPERATOR: frozenset(OPERATE),
    Role.INCIDENT_MANAGER: frozenset(OPERATE | TEAM | {Permission.CONFIRM_CLASSIFICATION, Permission.CHANGE_SEVERITY_PRIORITY,
                                                       Permission.VERIFY_RESOLUTIONS, Permission.CLOSE_REOPEN_INCIDENTS,
                                                       Permission.UPDATE_ESCALATIONS}),
    Role.KNOWLEDGE_MANAGER: frozenset(VIEW | TEAM | {Permission.MANAGE_KNOWLEDGE}),
    # Telemetry ingestion is for collectors (service accounts) only: a person or the assistant never writes telemetry.
    Role.SYSTEM_SERVICE: frozenset(TEAM | {Permission.VIEW_DIAGNOSTICS, Permission.VIEW_INCIDENTS, Permission.RUN_DIAGNOSTICS,
                                           Permission.CREATE_INCIDENTS, Permission.UPDATE_INCIDENTS, Permission.INGEST_TELEMETRY}),
    Role.AI_ASSISTANT: frozenset(TEAM | {Permission.VIEW_DIAGNOSTICS, Permission.VIEW_INCIDENTS, Permission.PROPOSE_RESOLUTIONS}),
}
ROLE_KINDS: dict[Role, ActorKind] = {
    Role.VIEWER: ActorKind.HUMAN, Role.OPERATOR: ActorKind.HUMAN, Role.INCIDENT_MANAGER: ActorKind.HUMAN,
    Role.KNOWLEDGE_MANAGER: ActorKind.HUMAN, Role.SYSTEM_SERVICE: ActorKind.SYSTEM, Role.AI_ASSISTANT: ActorKind.AI,
}


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    subject: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._@-]{0,63}$")]
    kind: ActorKind
    roles: list[Role] = Field(min_length=1, max_length=6)
    authenticated: bool = True

    @model_validator(mode="after")
    def check_roles(self) -> "Principal":
        mismatched = [role.value for role in self.roles if ROLE_KINDS[role] != self.kind]
        if mismatched:
            raise ValueError(f"roles {', '.join(mismatched)} cannot be held by {self.kind.value} principals")
        if self.kind != ActorKind.HUMAN and self.permissions & HUMAN_ONLY:
            raise ValueError("non-human principals cannot hold human-only permissions")
        return self

    @property
    def permissions(self) -> frozenset[Permission]:
        return frozenset().union(*(ROLE_PERMISSIONS[role] for role in self.roles))

    def actor(self) -> Actor:
        return Actor(kind=self.kind, actor_id=self.subject)


def authorize(principal: Any, permission: Permission) -> Principal:
    if not isinstance(principal, Principal) or not principal.authenticated:
        raise AuthenticationError()
    if permission in HUMAN_ONLY and principal.kind != ActorKind.HUMAN:
        raise AuthorizationError(f"{permission.value} requires a human principal")
    if permission not in principal.permissions:
        raise AuthorizationError(f"Principal lacks the {permission.value} permission")
    return principal


class TokenRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    token_hash: TOKEN_HASH
    principal: Principal
    expires_at: UtcDatetime | None = None


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class TokenAuthenticator:
    def __init__(self, records: list[TokenRecord], clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        hashes = [record.token_hash for record in records]
        if len(set(hashes)) != len(hashes):
            raise ValueError("token hashes must be unique")
        self.records = list(records)
        self.clock = clock

    def authenticate(self, token: Any) -> Principal:
        if not isinstance(token, str) or not token:
            raise AuthenticationError()
        if not MIN_TOKEN_LENGTH <= len(token) <= MAX_TOKEN_LENGTH:
            raise AuthenticationError("Invalid credentials")
        presented = hash_token(token)
        match = None
        for record in self.records:
            if hmac.compare_digest(record.token_hash, presented):
                match = record
        if match is None:
            raise AuthenticationError("Invalid credentials")
        if match.expires_at is not None and self.clock() >= match.expires_at:
            raise AuthenticationError("Credentials have expired")
        return match.principal


OPERATION_PERMISSIONS: dict[str, Permission] = {
    "get_incident": Permission.VIEW_INCIDENTS, "list_incidents": Permission.VIEW_INCIDENTS,
    "timeline": Permission.VIEW_INCIDENTS, "find_similar": Permission.VIEW_INCIDENTS,
    "diagnosis_history": Permission.VIEW_INCIDENTS, "resolution_history": Permission.VIEW_INCIDENTS,
    "recurring_incidents": Permission.VIEW_INCIDENTS,
    "create_incident": Permission.CREATE_INCIDENTS, "update_details": Permission.UPDATE_INCIDENTS,
    "change_status": Permission.UPDATE_INCIDENTS, "update_affected_assets": Permission.UPDATE_INCIDENTS,
    "create_escalation": Permission.UPDATE_INCIDENTS, "link_knowledge": Permission.UPDATE_INCIDENTS,
    "associate_diagnosis": Permission.RUN_DIAGNOSTICS, "run_diagnosis": Permission.RUN_DIAGNOSTICS,
    "propose_resolution": Permission.PROPOSE_RESOLUTIONS, "classify": Permission.CONFIRM_CLASSIFICATION,
    "change_severity": Permission.CHANGE_SEVERITY_PRIORITY, "change_priority": Permission.CHANGE_SEVERITY_PRIORITY,
    "verify_resolution": Permission.VERIFY_RESOLUTIONS, "close_incident": Permission.CLOSE_REOPEN_INCIDENTS,
    "reopen_incident": Permission.CLOSE_REOPEN_INCIDENTS, "update_escalation": Permission.UPDATE_ESCALATIONS,
}
READ_OPERATIONS = {"get_incident", "list_incidents", "timeline", "find_similar", "diagnosis_history", "resolution_history",
                   "recurring_incidents"}


class SecuredIncidentService:
    """Permission and ownership checks in front of IncidentService.

    An incident another principal cannot see is reported exactly like a missing one (404), so incident ids cannot be probed.
    """

    def __init__(self, service: IncidentService) -> None:
        self.service = service

    @staticmethod
    def team_scope(principal: Principal) -> bool:
        return Permission.VIEW_ALL_INCIDENTS in principal.permissions

    @classmethod
    def visibility(cls, principal: Principal) -> Callable[[Any], bool] | None:
        """None means every incident; otherwise a predicate over incidents or incident summaries."""
        if cls.team_scope(principal):
            return None
        subject = principal.subject
        return lambda item: (item.created_by_id if isinstance(item, Incident) else item.created_by) == subject \
            or item.assigned_owner == subject

    def visible_incident(self, principal: Principal, incident_id: str) -> Incident:
        incident = self.service.get_incident(incident_id)
        visible = self.visibility(principal)
        if visible is not None and not visible(incident):
            raise IncidentNotFoundError(f"Incident {incident_id} not found")
        return incident

    def call(self, operation: str, principal: Any, *args: Any, **kwargs: Any) -> Any:
        if operation not in OPERATION_PERMISSIONS:
            raise AuthorizationError("Unknown incident operation")
        authorized = authorize(principal, OPERATION_PERMISSIONS[operation])
        method = getattr(self.service, operation)
        if operation == "list_incidents":
            return method(*args, visible=self.visibility(authorized), **kwargs)
        if operation == "recurring_incidents":
            return method(*args, visible=self.visibility(authorized), **kwargs)
        incident_id, *rest = args
        incident = self.visible_incident(authorized, incident_id)
        if operation == "get_incident":
            return incident
        if operation == "find_similar":
            return method(incident_id, *rest, visible=self.visibility(authorized), **kwargs)
        if operation in READ_OPERATIONS:
            return method(incident_id, *rest, **kwargs)
        return method(incident_id, authorized.actor(), *rest, **kwargs)

    def create_incident(self, principal: Any, request: Any):
        authorized = authorize(principal, Permission.CREATE_INCIDENTS)
        return self.service.create_incident(request, authorized.actor(), visible=self.visibility(authorized))

    def update_escalation(self, principal: Any, incident_id: str, escalation_id: str, *args: Any, **kwargs: Any):
        authorized = authorize(principal, OPERATION_PERMISSIONS["update_escalation"])
        self.visible_incident(authorized, incident_id)
        return self.service.update_escalation(incident_id, escalation_id, authorized.actor(), *args, **kwargs)

    def __getattr__(self, operation: str) -> Callable[..., Any]:
        if operation not in OPERATION_PERMISSIONS:
            raise AttributeError(operation)
        return lambda principal, *args, **kwargs: self.call(operation, principal, *args, **kwargs)
