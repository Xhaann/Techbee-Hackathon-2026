import json
import threading
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import ValidationError

from app.diagnostics import ToolResult, ToolStatus
from app.engine.registry import REGISTRY, ToolSpec

MAX_TOOL_CALLS = 10
MAX_TOOL_REQUESTS = 20
MAX_ARGUMENT_CHARS = 4000
MAX_RESULT_CHARS = 12_000


@dataclass
class ToolCallRecord:
    call_id: str
    tool: str
    arguments: dict[str, Any]
    status: str
    result: ToolResult | None = None
    error_code: str | None = None
    error: str | None = None
    duplicate_of: str | None = None
    evidence_base: int = 0

    @property
    def succeeded(self) -> bool:
        return self.status == "executed" and self.result is not None and self.result.status == ToolStatus.SUCCESS


def truncate_lists(value: Any, limit: int) -> Any:
    if isinstance(value, dict):
        return {key: truncate_lists(item, limit) for key, item in value.items()}
    if isinstance(value, list):
        items = [truncate_lists(item, limit) for item in value[:limit]]
        if len(value) > limit:
            items.append(f"... {len(value) - limit} more items omitted")
        return items
    return value


def compact(payload: dict[str, Any]) -> str:
    text = json.dumps(payload, sort_keys=True)
    for limit in (25, 10, 5, 2):
        if len(text) <= MAX_RESULT_CHARS:
            return text
        text = json.dumps(truncate_lists(payload, limit), sort_keys=True)
    if len(text) <= MAX_RESULT_CHARS:
        return text
    reduced = {key: value for key, value in payload.items() if key != "data"} | {"data": "omitted: result too large"}
    return json.dumps(reduced, sort_keys=True)[:MAX_RESULT_CHARS]


class ToolObserver(Protocol):
    """Receives progress from a ToolExecutor. Called from the thread that runs the tool; must be thread-safe."""

    def started(self, call_id: str, tool: str, arguments: dict[str, Any]) -> None: ...

    def finished(self, record: ToolCallRecord) -> None: ...


class ToolExecutor:
    @staticmethod
    def validate_result(outcome: Any) -> ToolResult | None:
        if not isinstance(outcome, ToolResult):
            return None
        try:
            payload = outcome.model_dump(mode="json")
            json.dumps(payload)
            return ToolResult.model_validate(payload)
        except (ValidationError, TypeError, ValueError):
            return None

    def __init__(self, scenario_id: str, registry: dict[str, ToolSpec] = REGISTRY, max_calls: int = MAX_TOOL_CALLS,
                 observer: ToolObserver | None = None, cancel_event: threading.Event | None = None,
                 evidence_offset: int = 0) -> None:
        self.scenario_id = scenario_id
        self.evidence_offset = evidence_offset
        self.registry = registry
        self.max_calls = max_calls
        self.records: list[ToolCallRecord] = []
        self.requests = 0
        self.seen: dict[str, str] = {}
        self.observer = observer
        self.cancel_event = cancel_event

    def notify(self, method: str, *args: Any) -> None:
        if self.observer is None:
            return
        try:
            getattr(self.observer, method)(*args)
        except Exception:
            pass  # Progress reporting must never change what a tool call does.

    def append(self, record: ToolCallRecord) -> ToolCallRecord:
        record.evidence_base = self.evidence_offset
        self.records.append(record)
        self.notify("finished", record)
        return record

    @property
    def executed(self) -> list[ToolCallRecord]:
        return [record for record in self.records if record.status in ("executed", "failed")]

    @property
    def remaining(self) -> int:
        return self.max_calls - len(self.executed)

    def reject(self, tool: str, arguments: dict[str, Any], code: str, message: str, status: str = "rejected") -> ToolCallRecord:
        record = ToolCallRecord(call_id=f"C{len(self.records) + 1}", tool=tool, arguments=arguments, status=status,
                                error_code=code, error=message)
        return self.append(record)

    def execute(self, name: Any, arguments: Any) -> ToolCallRecord:
        self.requests += 1
        tool = name[:64] if isinstance(name, str) else "<invalid>"
        if self.cancel_event is not None and self.cancel_event.is_set():
            return self.reject(tool, {}, "CANCELLED", "The investigation was cancelled before this call ran")
        if self.requests > MAX_TOOL_REQUESTS:
            return self.reject(tool, {}, "REQUEST_LIMIT", "Maximum number of tool requests reached")
        if isinstance(arguments, str):
            if len(arguments) > MAX_ARGUMENT_CHARS:
                return self.reject(tool, {}, "INVALID_ARGUMENTS", "Tool arguments are too large")
            try:
                arguments = json.loads(arguments or "{}")
            except ValueError:
                return self.reject(tool, {}, "INVALID_ARGUMENTS", "Tool arguments are not valid JSON")
        if not isinstance(arguments, dict):
            return self.reject(tool, {}, "INVALID_ARGUMENTS", "Tool arguments must be a JSON object")
        spec = self.registry.get(tool)
        if spec is None:
            return self.reject(tool, {}, "UNKNOWN_TOOL", f"Tool '{tool}' is not registered")
        try:
            validated = spec.arguments.model_validate(arguments)
        except ValidationError as exc:
            fields = sorted({".".join(str(part) for part in error["loc"]) or "arguments" for error in exc.errors()})
            return self.reject(tool, {}, "INVALID_ARGUMENTS", f"Invalid arguments: {', '.join(fields)}")
        clean = validated.model_dump(exclude_none=True)
        key = json.dumps([tool, clean], sort_keys=True)
        if key in self.seen:
            record = self.reject(tool, clean, "DUPLICATE_CALL", f"Identical call already executed as {self.seen[key]}", "duplicate")
            record.duplicate_of = self.seen[key]
            return record
        if self.remaining <= 0:
            return self.reject(tool, clean, "BUDGET_EXHAUSTED", f"Tool call budget of {self.max_calls} is exhausted")
        call_id = f"C{len(self.records) + 1}"
        self.notify("started", call_id, tool, clean)
        try:
            outcome = spec.invoke(self.scenario_id, validated)
        except Exception:
            record = ToolCallRecord(call_id=call_id, tool=tool, arguments=clean, status="failed",
                                    error_code="TOOL_EXECUTION_ERROR", error="The tool raised an unexpected error")
        else:
            result = self.validate_result(outcome)
            if result is None:
                record = ToolCallRecord(call_id=call_id, tool=tool, arguments=clean, status="failed",
                                        error_code="TOOL_RESULT_INVALID", error="The tool returned an invalid result")
            else:
                record = ToolCallRecord(call_id=call_id, tool=tool, arguments=clean, status="executed", result=result,
                                        error_code=result.error.code if result.error else None,
                                        error=result.error.message if result.error else None)
        self.seen[key] = call_id
        return self.append(record)
