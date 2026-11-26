import hashlib
import hmac
from collections.abc import Callable
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.exceptions import AppError
from app.incidents.models import Actor, ActorKind
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
    CREATE_INCIDENTS = "create_incidents"
    UPDATE_INCIDENTS = "update_incidents"
    PROPOSE_RESOLUTIONS = "propose_resolutions"
    CONFIRM_CLASSIFICATION = "confirm_classification"
    CHANGE_SEVERITY_PRIORITY = "change_severity_priority"
    VERIFY_RESOLUTIONS = "verify_resolutions"
    CLOSE_REOPEN_INCIDENTS = "close_reopen_incidents"
    UPDATE_ESCALATIONS = "update_escalations"
    MANAGE_KNOWLEDGE = "manage_knowledge"


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
OPERATE = VIEW | {Permission.RUN_DIAGNOSTICS, Permission.CREATE_INCIDENTS, Permission.UPDATE_INCIDENTS, Permission.PROPOSE_RESOLUTIONS}
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset(VIEW),
    Role.OPERATOR: frozenset(OPERATE),
    Role.INCIDENT_MANAGER: frozenset(OPERATE | {Permission.CONFIRM_CLASSIFICATION, Permission.CHANGE_SEVERITY_PRIORITY,
                                                Permission.VERIFY_RESOLUTIONS, Permission.CLOSE_REOPEN_INCIDENTS,
                                                Permission.UPDATE_ESCALATIONS}),
    Role.KNOWLEDGE_MANAGER: frozenset(VIEW | {Permission.MANAGE_KNOWLEDGE}),
    Role.SYSTEM_SERVICE: frozenset({Permission.VIEW_DIAGNOSTICS, Permission.VIEW_INCIDENTS, Permission.RUN_DIAGNOSTICS,
                                    Permission.CREATE_INCIDENTS, Permission.UPDATE_INCIDENTS}),
    Role.AI_ASSISTANT: frozenset({Permission.VIEW_DIAGNOSTICS, Permission.VIEW_INCIDENTS, Permission.PROPOSE_RESOLUTIONS}),
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
    def __init__(self, service: IncidentService) -> None:
        self.service = service

    def call(self, operation: str, principal: Any, *args: Any, **kwargs: Any) -> Any:
        if operation not in OPERATION_PERMISSIONS:
            raise AuthorizationError("Unknown incident operation")
        authorized = authorize(principal, OPERATION_PERMISSIONS[operation])
        method = getattr(self.service, operation)
        if operation in READ_OPERATIONS:
            return method(*args, **kwargs)
        incident_id, *rest = args
        return method(incident_id, authorized.actor(), *rest, **kwargs)

    def create_incident(self, principal: Any, request: Any):
        authorized = authorize(principal, Permission.CREATE_INCIDENTS)
        return self.service.create_incident(request, authorized.actor())

    def update_escalation(self, principal: Any, incident_id: str, escalation_id: str, *args: Any, **kwargs: Any):
        authorized = authorize(principal, OPERATION_PERMISSIONS["update_escalation"])
        return self.service.update_escalation(incident_id, escalation_id, authorized.actor(), *args, **kwargs)

    def __getattr__(self, operation: str) -> Callable[..., Any]:
        if operation not in OPERATION_PERMISSIONS:
            raise AttributeError(operation)
        return lambda principal, *args, **kwargs: self.call(operation, principal, *args, **kwargs)
