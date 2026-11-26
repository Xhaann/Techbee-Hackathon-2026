"""In-memory conversation store with per-owner isolation and an event log for SSE replay.

All mutation happens on the event loop thread. Tool threads hand progress back with loop.call_soon_threadsafe.
"""
import asyncio
import secrets
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from app.conversation.models import (
    ActiveTurn,
    ConversationContext,
    ConversationEvent,
    ConversationSummary,
    ConversationView,
    Investigation,
    Message,
)
from app.core.exceptions import AppError
from app.engine.schema import Diagnosis

MAX_CONVERSATIONS_PER_OWNER = 30
MAX_CONVERSATIONS = 2000
MAX_MESSAGES = 200
MAX_INVESTIGATIONS = 30
MAX_EVENTS = 3000
TERMINAL_EVENTS = frozenset({"turn.completed", "turn.failed"})


def now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str, size: int) -> str:
    return f"{prefix}-{secrets.token_hex(size)}"


@dataclass
class TurnHandle:
    turn_id: str
    started_at: datetime
    cancel_event: threading.Event = field(default_factory=threading.Event)
    task: asyncio.Task | None = None
    investigation_id: str | None = None
    cancel_requested: bool = False


@dataclass
class ConversationState:
    conversation_id: str
    owner: str
    created_at: datetime
    updated_at: datetime
    mode: Literal["auto", "rule_based"]
    title: str
    context: ConversationContext
    messages: list[Message] = field(default_factory=list)
    investigations: dict[str, Investigation] = field(default_factory=dict)
    diagnoses: dict[str, Diagnosis] = field(default_factory=dict)
    fingerprints: dict[str, str] = field(default_factory=dict)
    events: deque[ConversationEvent] = field(default_factory=lambda: deque(maxlen=MAX_EVENTS))
    seq: int = 0
    subscribers: set[asyncio.Queue] = field(default_factory=set)
    active: TurnHandle | None = None

    def add_message(self, message: Message) -> None:
        self.messages.append(message)
        del self.messages[:-MAX_MESSAGES]
        self.updated_at = now()

    def add_investigation(self, investigation: Investigation) -> None:
        self.investigations[investigation.investigation_id] = investigation
        while len(self.investigations) > MAX_INVESTIGATIONS:
            oldest = next(iter(self.investigations))
            self.investigations.pop(oldest)
            self.diagnoses.pop(oldest, None)
            self.fingerprints.pop(oldest, None)

    def active_view(self) -> ActiveTurn | None:
        if self.active is None:
            return None
        return ActiveTurn(turn_id=self.active.turn_id, started_at=self.active.started_at,
                          investigation_id=self.active.investigation_id)

    def summary(self) -> ConversationSummary:
        return ConversationSummary(conversation_id=self.conversation_id, title=self.title, incident_id=self.context.incident_id,
                                   scenario_id=self.context.scenario_id, created_at=self.created_at, updated_at=self.updated_at,
                                   message_count=len(self.messages), active_turn=self.active_view())

    def view(self, model_available: bool) -> ConversationView:
        return ConversationView(**self.summary().model_dump(), mode=self.mode, messages=list(self.messages),
                                context=self.context.model_copy(deep=True),
                                investigations=[item.summary() for item in self.investigations.values()],
                                last_event_seq=self.seq, model_available=model_available)


class ConversationNotFound(AppError):
    def __init__(self) -> None:
        super().__init__("Conversation not found", code="NOT_FOUND", status_code=404)


class ConversationStore:
    def __init__(self, max_per_owner: int = MAX_CONVERSATIONS_PER_OWNER, max_total: int = MAX_CONVERSATIONS) -> None:
        self.max_per_owner = max_per_owner
        self.max_total = max_total
        self.conversations: dict[str, ConversationState] = {}

    def create(self, owner: str, context: ConversationContext, mode: Literal["auto", "rule_based"], title: str) -> ConversationState:
        moment = now()
        state = ConversationState(conversation_id=new_id("CNV", 8), owner=owner, created_at=moment, updated_at=moment, mode=mode,
                                  title=title[:200], context=context)
        self.conversations[state.conversation_id] = state
        self.evict(owner)
        return state

    def evict(self, owner: str) -> None:
        def idle(items: list[ConversationState]) -> list[ConversationState]:
            return sorted((item for item in items if item.active is None), key=lambda item: item.updated_at)
        mine = [item for item in self.conversations.values() if item.owner == owner]
        for item in idle(mine)[:max(0, len(mine) - self.max_per_owner)]:
            self.conversations.pop(item.conversation_id, None)
        everyone = list(self.conversations.values())
        for item in idle(everyone)[:max(0, len(everyone) - self.max_total)]:
            self.conversations.pop(item.conversation_id, None)

    def get(self, owner: str, conversation_id: str) -> ConversationState:
        state = self.conversations.get(conversation_id)
        # Another owner's conversation is reported exactly like a missing one, so ids can't be probed.
        if state is None or state.owner != owner:
            raise ConversationNotFound()
        return state

    def owned(self, owner: str, incident_id: str | None = None) -> list[ConversationState]:
        items = [item for item in self.conversations.values()
                 if item.owner == owner and (incident_id is None or item.context.incident_id == incident_id)]
        return sorted(items, key=lambda item: item.updated_at, reverse=True)

    def delete(self, owner: str, conversation_id: str) -> None:
        state = self.get(owner, conversation_id)
        if state.active is not None:
            state.active.cancel_event.set()
            if state.active.task is not None:
                state.active.task.cancel()
        self.conversations.pop(conversation_id, None)

    @staticmethod
    def emit(state: ConversationState, event: str, turn_id: str | None, data: dict[str, Any]) -> ConversationEvent:
        state.seq += 1
        record = ConversationEvent(seq=state.seq, event=event, conversation_id=state.conversation_id, turn_id=turn_id, at=now(),
                                   data=data)
        state.events.append(record)
        for queue in list(state.subscribers):
            queue.put_nowait(record)
        return record

    @staticmethod
    def subscribe(state: ConversationState) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        state.subscribers.add(queue)
        return queue

    @staticmethod
    def unsubscribe(state: ConversationState, queue: asyncio.Queue) -> None:
        state.subscribers.discard(queue)

    @staticmethod
    def replay(state: ConversationState, after: int) -> tuple[list[ConversationEvent], bool]:
        events = [event for event in state.events if event.seq > after]
        truncated = bool(state.events) and state.events[0].seq > after + 1
        return events, truncated

    def shutdown(self) -> None:
        for state in self.conversations.values():
            if state.active is not None:
                state.active.cancel_event.set()
                if state.active.task is not None:
                    state.active.task.cancel()
