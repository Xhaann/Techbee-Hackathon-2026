from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Request, Response
from pydantic import Field
from starlette.concurrency import run_in_threadpool

from app.api.dependencies import CurrentPrincipal, ServicesDependency, bearer_token
from app.api.schemas import ApiModel, PrincipalView
from app.core.exceptions import AppError
from app.security.permissions import AuthenticationError, Principal
from app.security.tokens import TokenStoreError, issue_token, revoke_token
from app.security.users import UserStoreError, authenticate_user, load_users, normalise, users_file

router = APIRouter(prefix="/auth", tags=["auth"])


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
    accounts = users_file(settings)
    if accounts is None or not settings.auth_tokens_file:
        raise AppError("Sign-in is not configured on the server", code="LOGIN_NOT_CONFIGURED", status_code=503)
    key = normalise(body.username)
    wait = registry.login_throttle.retry_after(key)
    if wait is not None:
        raise AppError("Too many failed sign-in attempts for this account. Try again later.", code="LOGIN_THROTTLED",
                       status_code=429, headers={"retry-after": str(int(wait) + 1)})
    try:
        if not load_users(accounts):
            raise AppError("No user accounts are configured on the server", code="LOGIN_NOT_CONFIGURED", status_code=503)
        principal = authenticate_user(accounts, body.username, body.password)
    except UserStoreError:
        raise AppError("Authentication store is unavailable", code="AUTHENTICATION_UNAVAILABLE", status_code=503) from None
    if principal is None:
        registry.login_throttle.failure(key)
        raise AuthenticationError("Invalid username or password")
    registry.login_throttle.success(key)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        token = issue_token(Path(settings.auth_tokens_file), principal, settings.session_hours, now=now)
    except (OSError, TokenStoreError):
        raise AppError("Could not start a session", code="SESSION_UNAVAILABLE", status_code=503) from None
    return LoginResponse(token=token, expires_at=now + timedelta(hours=settings.session_hours), principal=view(principal))


@router.post("/logout", status_code=204, responses={204: {"description": "The presented token was revoked"}})
async def logout(request: Request, principal: CurrentPrincipal, registry: ServicesDependency) -> Response:
    token = bearer_token(request)
    if token and registry.settings.auth_tokens_file:
        try:
            await run_in_threadpool(revoke_token, Path(registry.settings.auth_tokens_file), token)
        except (OSError, TokenStoreError):
            raise AppError("Could not end the session", code="SESSION_UNAVAILABLE", status_code=503) from None
    return Response(status_code=204)
