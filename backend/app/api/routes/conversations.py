import asyncio
from collections.abc import AsyncIterator
from typing import Annotated, Literal

from fastapi import APIRouter, Path, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import Field, model_validator

from app.api.dependencies import CurrentPrincipal, PageDependency, ServicesDependency
from app.api.schemas import ApiModel, AttachedIncident, Page, Version
from app.conversation.models import (
    ConversationContext,
    ConversationEvent,
    ConversationSummary,
    ConversationView,
    Investigation,
    QuickAction,
    TurnResult,
)
from app.conversation.store import TERMINAL_EVENTS, ConversationState
from app.incidents.models import IncidentId
from app.network.models import Identifier
from app.reasoning.report import ReasoningReport
from app.security.permissions import Permission, authorize

router = APIRouter(prefix="/conversations", tags=["conversations"])

ConversationPath = Annotated[str, Path(pattern=r"^CNV-[0-9a-f]{16}$")]
InvestigationPath = Annotated[str, Path(pattern=r"^INV-[0-9a-f]{12}$")]
HEARTBEAT_SECONDS = 15.0
SSE_HEADERS = {"Cache-Control": "no-store", "X-Accel-Buffering": "no"}


class ConversationCreateRequest(ApiModel):
    incident_id: IncidentId | None = None
    scenario_id: Annotated[Identifier, Field(max_length=64)] | None = None
    mode: Literal["auto", "rule_based"] = "auto"


class MessageCreateRequest(ApiModel):
    content: Annotated[str, Field(max_length=4000)] | None = None
    action: QuickAction | None = None
    stream: bool = False

    @model_validator(mode="after")
    def content_or_action(self) -> "MessageCreateRequest":
        if not (self.content and self.content.strip()) and self.action is None:
            raise ValueError("a message needs content or a quick action")
        return self


class CancelResponse(ApiModel):
    cancelled: bool
    turn_id: str | None
    investigation_id: str | None


class AttachRequest(ApiModel):
    expected_version: Version


def sse(event: ConversationEvent) -> bytes:
    return f"id: {event.seq}\nevent: {event.event}\ndata: {event.model_dump_json()}\n\n".encode()


async def event_stream(registry, state: ConversationState, after: int, turn_id: str | None) -> AsyncIterator[bytes]:
    store = registry.conversations.store
    queue = store.subscribe(state)
    target = turn_id or (state.active.turn_id if state.active else None)
    try:
        events, truncated = store.replay(state, after)
        if truncated:
            yield b"event: replay.truncated\ndata: {}\n\n"
        for event in events:
            yield sse(event)
            after = event.seq
            if event.event in TERMINAL_EVENTS and event.turn_id == target:
                return
        if target is None:
            return
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
            except asyncio.TimeoutError:
                yield b": keep-alive\n\n"
                if state.active is None or state.active.turn_id != target:
                    return
                continue
            if event.seq <= after:
                continue
            yield sse(event)
            after = event.seq
            if event.event in TERMINAL_EVENTS and event.turn_id == target:
                return
    finally:
        store.unsubscribe(state, queue)


def owned(registry, principal, conversation_id: str) -> ConversationState:
    authorize(principal, Permission.VIEW_DIAGNOSTICS)
    return registry.conversations.store.get(principal.subject, conversation_id)


@router.post("", response_model=ConversationView, status_code=201)
async def create(body: ConversationCreateRequest, principal: CurrentPrincipal, registry: ServicesDependency) -> ConversationView:
    authorize(principal, Permission.VIEW_DIAGNOSTICS)
    service = registry.conversations
    state = await service.create(principal, body.incident_id, body.scenario_id, body.mode)
    return state.view(service.model_available)


@router.get("", response_model=Page[ConversationSummary])
def list_conversations(principal: CurrentPrincipal, registry: ServicesDependency, page: PageDependency,
                       incident_id: Annotated[IncidentId | None, Query()] = None) -> dict:
    authorize(principal, Permission.VIEW_DIAGNOSTICS)
    states = registry.conversations.store.owned(principal.subject, incident_id)
    return page.slice([state.summary() for state in states])


@router.get("/{conversation_id}", response_model=ConversationView)
def get(conversation_id: ConversationPath, principal: CurrentPrincipal, registry: ServicesDependency) -> ConversationView:
    state = owned(registry, principal, conversation_id)
    return state.view(registry.conversations.model_available)


@router.delete("/{conversation_id}", status_code=204)
def delete(conversation_id: ConversationPath, principal: CurrentPrincipal, registry: ServicesDependency) -> Response:
    authorize(principal, Permission.VIEW_DIAGNOSTICS)
    registry.conversations.store.delete(principal.subject, conversation_id)
    return Response(status_code=204)


@router.post("/{conversation_id}/messages", response_model=TurnResult,
             responses={200: {"content": {"text/event-stream": {}}, "description": "TurnResult, or an SSE stream when requested"}})
async def send(conversation_id: ConversationPath, body: MessageCreateRequest, request: Request, principal: CurrentPrincipal,
               registry: ServicesDependency):
    state = owned(registry, principal, conversation_id)
    service = registry.conversations
    after = state.seq
    handle = service.start_turn(state, principal, body.content, body.action)
    if body.stream or "text/event-stream" in request.headers.get("accept", ""):
        return StreamingResponse(event_stream(registry, state, after, handle.turn_id), media_type="text/event-stream",
                                 headers=SSE_HEADERS)
    # The turn keeps running if this request goes away; its events and result stay replayable.
    return await asyncio.shield(handle.task)


@router.get("/{conversation_id}/events", responses={200: {"content": {"text/event-stream": {}}}})
async def events(conversation_id: ConversationPath, principal: CurrentPrincipal, registry: ServicesDependency,
                 after: Annotated[int, Query(ge=0)] = 0) -> StreamingResponse:
    state = owned(registry, principal, conversation_id)
    return StreamingResponse(event_stream(registry, state, after, None), media_type="text/event-stream", headers=SSE_HEADERS)


@router.post("/{conversation_id}/cancel", response_model=CancelResponse)
def cancel(conversation_id: ConversationPath, principal: CurrentPrincipal, registry: ServicesDependency) -> CancelResponse:
    state = owned(registry, principal, conversation_id)
    handle = registry.conversations.cancel(state)
    return CancelResponse(cancelled=handle is not None, turn_id=handle.turn_id if handle else None,
                          investigation_id=handle.investigation_id if handle else None)


@router.get("/{conversation_id}/context", response_model=ConversationContext)
def context(conversation_id: ConversationPath, principal: CurrentPrincipal, registry: ServicesDependency) -> ConversationContext:
    return owned(registry, principal, conversation_id).context


@router.delete("/{conversation_id}/context", response_model=ConversationContext)
def reset_context(conversation_id: ConversationPath, principal: CurrentPrincipal, registry: ServicesDependency) -> ConversationContext:
    state = owned(registry, principal, conversation_id)
    return registry.conversations.reset_context(state)


@router.get("/{conversation_id}/investigations/{investigation_id}/reasoning", response_model=ReasoningReport)
def investigation_reasoning(conversation_id: ConversationPath, investigation_id: InvestigationPath, principal: CurrentPrincipal,
                            registry: ServicesDependency) -> ReasoningReport:
    """Probabilities, contradictions, causal chain, specialist reviews, plan and self-evaluation for one investigation."""
    state = owned(registry, principal, conversation_id)
    found = state.investigations.get(investigation_id)
    if found is None or found.reasoning is None:
        from app.api.dependencies import not_found
        raise not_found("No reasoning for that investigation")
    return found.reasoning


@router.get("/{conversation_id}/investigations/{investigation_id}", response_model=Investigation)
def investigation(conversation_id: ConversationPath, investigation_id: InvestigationPath, principal: CurrentPrincipal,
                  registry: ServicesDependency) -> Investigation:
    state = owned(registry, principal, conversation_id)
    found = state.investigations.get(investigation_id)
    if found is None:
        from app.api.dependencies import not_found
        raise not_found("Investigation not found")
    return found


@router.post("/{conversation_id}/investigations/{investigation_id}/attach", response_model=AttachedIncident)
async def attach(conversation_id: ConversationPath, investigation_id: InvestigationPath, body: AttachRequest,
                 principal: CurrentPrincipal, registry: ServicesDependency) -> AttachedIncident:
    """Human-approved: saves a conversation diagnosis to the linked incident. Never called by the assistant itself."""
    state = owned(registry, principal, conversation_id)
    authorize(principal, Permission.RUN_DIAGNOSTICS)
    with registry.in_flight.claim(f"attach:{investigation_id}", "This investigation is already being saved"):
        updated = await registry.conversations.attach(state, principal, investigation_id, body.expected_version)
    return AttachedIncident(incident_id=updated.incident_id, version=updated.version, status=updated.status.value,
                            active_diagnosis_id=updated.active_diagnosis_id)
