import hmac
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter
from pydantic import Field

from app.api.dependencies import CurrentPrincipal, ServicesDependency
from app.api.schemas import ApiModel, PrincipalView
from app.core.exceptions import AppError
from app.incidents.models import ActorKind
from app.security.permissions import AuthenticationError, Principal, Role
from app.security.tokens import TokenStoreError, issue_token

router = APIRouter(prefix="/auth", tags=["auth"])

ADMIN_SUBJECT = "admin"
ADMIN_ROLES = [Role.INCIDENT_MANAGER, Role.KNOWLEDGE_MANAGER]


class LoginRequest(ApiModel):
    username: Annotated[str, Field(min_length=1, max_length=128)]
    password: Annotated[str, Field(min_length=1, max_length=256)]


class LoginResponse(ApiModel):
    token: str
    expires_at: datetime
    principal: PrincipalView


def view(principal: Principal) -> PrincipalView:
    return PrincipalView(subject=principal.subject, kind=principal.kind.value, roles=[role.value for role in principal.roles],
                         permissions=sorted(permission.value for permission in principal.permissions),
                         authenticated=principal.authenticated)


@router.post("/verify", response_model=PrincipalView)
def verify(principal: CurrentPrincipal) -> PrincipalView:
    return view(principal)


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, registry: ServicesDependency) -> LoginResponse:
    settings = registry.settings
    if not settings.admin_username or settings.admin_password is None or not settings.auth_tokens_file:
        raise AppError("Sign-in is not configured on the server", code="LOGIN_NOT_CONFIGURED", status_code=503)
    username_ok = hmac.compare_digest(body.username.encode(), settings.admin_username.encode())
    password_ok = hmac.compare_digest(body.password.encode(), settings.admin_password.get_secret_value().encode())
    if not (username_ok and password_ok):
        raise AuthenticationError("Invalid username or password")
    principal = Principal(subject=ADMIN_SUBJECT, kind=ActorKind.HUMAN, roles=ADMIN_ROLES)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        token = issue_token(Path(settings.auth_tokens_file), principal, settings.admin_session_hours, now=now)
    except (OSError, TokenStoreError):
        raise AppError("Could not start a session", code="SESSION_UNAVAILABLE", status_code=503) from None
    return LoginResponse(token=token, expires_at=now + timedelta(hours=settings.admin_session_hours), principal=view(principal))
