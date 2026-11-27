import re
import threading
import time
import uuid
from collections import OrderedDict, deque
from collections.abc import Callable

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.exceptions import error_response

DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")
BASE_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "cross-origin-opener-policy": "same-origin",
}
API_CSP = "default-src 'none'; frame-ancestors 'none'"
MAX_TRACKED_CLIENTS = 10_000
REQUEST_ID = re.compile(r"^[A-Za-z0-9-]{8,64}$")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        documentation = scope["path"].startswith(DOCS_PATHS)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                extra = dict(BASE_HEADERS)
                if not documentation:
                    extra["content-security-policy"] = API_CSP
                    extra["cache-control"] = "no-store"
                headers += [(name.encode(), value.encode()) for name, value in extra.items() if name.encode() not in present]
                message = message | {"headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestSizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope.get("headers", [])).get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.max_bytes):
            await self.reject(scope, receive, send)
            return
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                await self.app(scope, receive, send)
                return
            size += len(message.get("body", b""))
            if size > self.max_bytes:
                await self.reject(scope, receive, send)
                return
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    async def reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = error_response(413, "PAYLOAD_TOO_LARGE", f"Request body exceeds {self.max_bytes} bytes")
        await response(scope, receive, send)


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float, clock: Callable[[], float] = time.monotonic,
                 max_clients: int = MAX_TRACKED_CLIENTS) -> None:
        self.limit = limit
        self.window = window_seconds
        self.clock = clock
        self.max_clients = max_clients
        self.hits: OrderedDict[str, deque[float]] = OrderedDict()
        self.lock = threading.Lock()

    def check(self, key: str) -> float | None:
        with self.lock:
            now = self.clock()
            hits = self.hits.pop(key, deque())
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                self.hits[key] = hits
                return max(0.0, self.window - (now - hits[0]))
            hits.append(now)
            self.hits[key] = hits
            while len(self.hits) > self.max_clients:
                self.hits.popitem(last=False)
            return None


class LoginThrottle:
    """Refuses further sign-in attempts for a username after repeated failures inside a sliding window."""

    def __init__(self, max_failures: int, window_seconds: float, clock: Callable[[], float] = time.monotonic,
                 max_keys: int = MAX_TRACKED_CLIENTS) -> None:
        self.max_failures = max_failures
        self.window = window_seconds
        self.clock = clock
        self.max_keys = max_keys
        self.failures: OrderedDict[str, deque[float]] = OrderedDict()
        self.lock = threading.Lock()

    def _recent(self, key: str, now: float) -> deque[float]:
        hits = self.failures.pop(key, deque())
        while hits and now - hits[0] >= self.window:
            hits.popleft()
        return hits

    def retry_after(self, key: str) -> float | None:
        with self.lock:
            now = self.clock()
            hits = self._recent(key, now)
            if hits:
                self.failures[key] = hits
            if len(hits) >= self.max_failures:
                return max(0.0, self.window - (now - hits[0]))
            return None

    def failure(self, key: str) -> None:
        with self.lock:
            now = self.clock()
            hits = self._recent(key, now)
            hits.append(now)
            self.failures[key] = hits
            while len(self.failures) > self.max_keys:
                self.failures.popitem(last=False)

    def success(self, key: str) -> None:
        with self.lock:
            self.failures.pop(key, None)


class ConcurrencyLimiter:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.active = 0
        self.lock = threading.Lock()

    def acquire(self) -> bool:
        with self.lock:
            if self.active >= self.limit:
                return False
            self.active += 1
            return True

    def release(self) -> None:
        with self.lock:
            self.active = max(0, self.active - 1)


def client_key(scope: Scope) -> str:
    client = scope.get("client")
    return client[0] if client else "unknown"


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp, limiter: RateLimiter) -> None:
        self.app = app
        self.limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        retry_after = self.limiter.check(client_key(scope))
        if retry_after is not None:
            response = error_response(429, "RATE_LIMITED", "Too many requests", headers={"retry-after": str(int(retry_after) + 1)})
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class ConcurrencyLimitMiddleware:
    def __init__(self, app: ASGIApp, limiter: ConcurrencyLimiter) -> None:
        self.app = app
        self.limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if not self.limiter.acquire():
            response = error_response(503, "SERVER_BUSY", "Too many concurrent requests")
            await response(scope, receive, send)
            return
        try:
            await self.app(scope, receive, send)
        finally:
            self.limiter.release()


class RequestIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        supplied = dict(scope.get("headers", [])).get(b"x-request-id", b"").decode("latin-1")
        request_id = supplied if REQUEST_ID.match(supplied) else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [(name, value) for name, value in message.get("headers", []) if name.lower() != b"x-request-id"]
                message = message | {"headers": headers + [(b"x-request-id", request_id.encode())]}
            await send(message)

        await self.app(scope, receive, send_with_id)
