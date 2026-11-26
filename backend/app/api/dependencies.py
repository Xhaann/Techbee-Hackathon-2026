import threading
from functools import cached_property
from pathlib import Path
from typing import Annotated

from fastapi import Depends, Query, Request

from app.advanced import AdvancedDiagnosisEngine
from app.agent.runtime import AgentResources
from app.core.config import Settings
from app.core.exceptions import AppError
from app.diagnostics import ToolResult
from app.engine import DiagnosisEngine
from app.engine.providers import ChatCompletionsProvider, ProviderError, build_provider
from app.incidents import IncidentService, build_incident_service
from app.knowledge import KnowledgeService
from app.network.models import Identifier
from app.network.repository import list_scenario_ids
from app.security.api import ConcurrencyLimiter
from app.security.permissions import AuthenticationError, Permission, Principal, SecuredIncidentService, TokenAuthenticator, authorize
from app.security.tokens import TokenStoreError, load_token_records

MAX_PAGE_SIZE = 100
MAX_OFFSET = 10_000


class Services:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.agent = AgentResources(settings)
        self.agent_runs = ConcurrencyLimiter(settings.max_concurrent_agent_runs)
        self.token_state: tuple[tuple[int, int] | None, TokenAuthenticator] | None = None
        self.token_lock = threading.Lock()

    @cached_property
    def incidents(self) -> IncidentService:
        return build_incident_service(self.settings)

    @cached_property
    def secured_incidents(self) -> SecuredIncidentService:
        return SecuredIncidentService(self.incidents)

    @cached_property
    def knowledge(self) -> KnowledgeService:
        return KnowledgeService()

    @cached_property
    def conversations(self):
        from app.conversation.orchestrator import ConversationService
        return ConversationService(self)

    def shutdown_conversations(self) -> None:
        if "conversations" in self.__dict__:
            self.conversations.store.shutdown()

    def authenticator(self) -> TokenAuthenticator:
        if not self.settings.auth_tokens_file:
            return TokenAuthenticator([])
        path = Path(self.settings.auth_tokens_file)
        try:
            info = path.lstat()
            signature = (info.st_mtime_ns, info.st_size)
        except FileNotFoundError:
            signature = None
        with self.token_lock:
            if self.token_state is None or self.token_state[0] != signature:
                try:
                    self.token_state = (signature, TokenAuthenticator(load_token_records(path)))
                except (OSError, TokenStoreError, ValueError):
                    self.token_state = None
                    raise AppError("Authentication store is unavailable", code="AUTHENTICATION_UNAVAILABLE",
                                   status_code=503) from None
            return self.token_state[1]

    def provider(self) -> ChatCompletionsProvider | None:
        if self.settings.ai_provider == "disabled":
            return None
        try:
            return build_provider(self.settings)
        except ProviderError:
            raise AppError("The configured AI provider is unavailable", code="AI_PROVIDER_UNAVAILABLE", status_code=503) from None

    def diagnosis_engine(self) -> DiagnosisEngine:
        return DiagnosisEngine(self.provider(), self.knowledge.diagnosis_retriever())

    def advanced_engine(self) -> AdvancedDiagnosisEngine:
        return AdvancedDiagnosisEngine(self.provider(), self.knowledge, self.incidents)


def services(request: Request) -> Services:
    return request.app.state.services


ServicesDependency = Annotated[Services, Depends(services)]


def bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization")
    if header is None:
        return None
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthenticationError("Authorization header must use the Bearer scheme")
    return token.strip()


def current_principal(request: Request, registry: ServicesDependency) -> Principal:
    return registry.authenticator().authenticate(bearer_token(request))


def require(permission: Permission):
    def dependency(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
        return authorize(principal, permission)
    return dependency


CurrentPrincipal = Annotated[Principal, Depends(current_principal)]


class Pagination:
    def __init__(self, limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
                 offset: Annotated[int, Query(ge=0, le=MAX_OFFSET)] = 0) -> None:
        self.limit = limit
        self.offset = offset

    def slice(self, items: list) -> dict:
        return {"items": items[self.offset:self.offset + self.limit], "total": len(items), "limit": self.limit, "offset": self.offset}


PageDependency = Annotated[Pagination, Depends()]


def scenario(scenario_id: Annotated[Identifier, Query(max_length=64)] = "BASELINE") -> str:
    if scenario_id not in list_scenario_ids():
        raise AppError(f"Unknown scenario '{scenario_id}'", code="NOT_FOUND", status_code=404)
    return scenario_id


ScenarioDependency = Annotated[str, Depends(scenario)]


TOOL_ERROR_STATUS = {"NOT_FOUND": 404, "INVALID_ARGUMENT": 422, "DATA_UNAVAILABLE": 503}


def tool_data(result: ToolResult) -> ToolResult:
    if result.error is not None:
        raise AppError(result.error.message, code=result.error.code, status_code=TOOL_ERROR_STATUS.get(result.error.code, 400))
    return result


def not_found(message: str) -> AppError:
    return AppError(message, code="NOT_FOUND", status_code=404)


def invalid(message: str) -> AppError:
    return AppError(message, code="VALIDATION_ERROR", status_code=422)
