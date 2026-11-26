import asyncio

import pytest
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.core.config import Settings
from app.core.exceptions import AppError
from app.main import create_app
from app.security.api import ConcurrencyLimiter, ConcurrencyLimitMiddleware, RateLimiter, RequestSizeLimitMiddleware
from verification.api.helpers import EXPECTED_ROUTES, route_surface

SECURITY_HEADERS = {"x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "no-referrer"}


def client(**settings: object) -> TestClient:
    return TestClient(create_app(Settings(_env_file=None, **settings)), raise_server_exceptions=False)


def echo_app(max_bytes: int) -> TestClient:
    async def echo(request: Request) -> JSONResponse:
        return JSONResponse({"size": len(await request.body())})
    return TestClient(RequestSizeLimitMiddleware(Starlette(routes=[Route("/echo", echo, methods=["POST"])]), max_bytes))


def test_health_still_works_with_security_headers() -> None:
    response = client().get("/health")
    assert response.status_code == 200 and response.json() == {"status": "healthy"}
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    assert response.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert response.headers["cache-control"] == "no-store"


def test_documentation_keeps_working_without_strict_csp() -> None:
    response = client().get("/docs")
    assert response.status_code == 200 and "content-security-policy" not in response.headers
    assert response.headers["x-frame-options"] == "DENY"


def test_error_responses_carry_headers_and_contract() -> None:
    response = client().get("/missing")
    assert response.status_code == 404 and response.json() == {"error": {"code": "NOT_FOUND", "message": "Not Found"}}
    assert response.headers["x-content-type-options"] == "nosniff"


def test_declared_oversized_request_is_rejected() -> None:
    response = client(max_request_bytes=1024).post("/health", content=b"x" * 2048, headers={"content-type": "application/json"})
    assert response.status_code == 413
    assert response.json() == {"error": {"code": "PAYLOAD_TOO_LARGE", "message": "Request body exceeds 1024 bytes"}}
    assert response.headers["x-frame-options"] == "DENY"
    bogus = client(max_request_bytes=1024).post("/health", content=b"{}", headers={"content-length": "abc"})
    assert bogus.status_code in (400, 413)


def test_streamed_oversized_request_is_rejected_while_reading() -> None:
    app = echo_app(1024)
    assert app.post("/echo", content=b"x" * 1000).json() == {"size": 1000}
    streamed = app.post("/echo", content=iter([b"x" * 600, b"x" * 600]))
    assert streamed.status_code == 413 and streamed.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_rate_limit_rejects_excess_requests_with_standard_error() -> None:
    limited = client(rate_limit_requests=3, rate_limit_window_seconds=60)
    assert [limited.get("/health").status_code for _ in range(3)] == [200, 200, 200]
    blocked = limited.get("/health")
    assert blocked.status_code == 429 and blocked.json() == {"error": {"code": "RATE_LIMITED", "message": "Too many requests"}}
    assert int(blocked.headers["retry-after"]) >= 1 and blocked.headers["x-content-type-options"] == "nosniff"


def test_rate_limit_ignores_client_supplied_identity() -> None:
    limited = client(rate_limit_requests=2, rate_limit_window_seconds=60)
    codes = [limited.get("/health", headers={"x-forwarded-for": f"10.0.0.{n}", "x-real-ip": f"10.1.0.{n}"}).status_code
             for n in range(4)]
    assert codes == [200, 200, 429, 429]


def test_rate_limiter_window_and_memory_bounds() -> None:
    now = [0.0]
    limiter = RateLimiter(2, 10, clock=lambda: now[0], max_clients=3)
    assert limiter.check("a") is None and limiter.check("a") is None and limiter.check("a") == 10
    now[0] = 10.0
    assert limiter.check("a") is None
    for key in ("b", "c", "d", "e"):
        limiter.check(key)
    assert len(limiter.hits) == 3 and "a" not in limiter.hits


def test_concurrency_limit_rejects_when_saturated() -> None:
    limiter = ConcurrencyLimiter(1)

    async def ok(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True})
    app = TestClient(ConcurrencyLimitMiddleware(Starlette(routes=[Route("/", ok)]), limiter))
    assert app.get("/").status_code == 200 and limiter.active == 0
    assert limiter.acquire()
    busy = app.get("/")
    assert busy.status_code == 503 and busy.json() == {"error": {"code": "SERVER_BUSY", "message": "Too many concurrent requests"}}
    limiter.release()
    assert app.get("/").status_code == 200


def test_concurrency_slot_released_after_errors() -> None:
    limiter = ConcurrencyLimiter(1)

    async def boom(request: Request) -> JSONResponse:
        raise RuntimeError("failure")
    app = TestClient(ConcurrencyLimitMiddleware(Starlette(routes=[Route("/", boom)]), limiter), raise_server_exceptions=False)
    assert app.get("/").status_code == 500 and limiter.active == 0


def test_error_messages_are_redacted() -> None:
    app = create_app(Settings(_env_file=None))

    @app.get("/leak-check")
    async def leak() -> None:
        raise AppError("Provider rejected key sk-proj-ABCDEFGHIJKLMNOP1234 for password: hunter2", code="UPSTREAM", status_code=502)
    body = TestClient(app).get("/leak-check").json()
    assert "ABCDEFGHIJKL" not in body["error"]["message"] and "hunter2" not in body["error"]["message"]
    assert "[redacted]" in body["error"]["message"]


def test_cors_restrictions_remain() -> None:
    allowed = client().options("/health", headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"})
    denied = client().options("/health", headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"})
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:3000" and denied.status_code == 400


def test_api_surface_unchanged() -> None:
    assert route_surface(client()) == EXPECTED_ROUTES


@pytest.mark.parametrize("values", [{"max_request_bytes": 10}, {"rate_limit_requests": 0}, {"max_concurrent_requests": 0},
                                    {"rate_limit_window_seconds": 0}])
def test_security_settings_are_validated(values: dict) -> None:
    with pytest.raises(ValueError):
        Settings(_env_file=None, **values)


def test_middleware_ignores_non_http_scopes() -> None:
    events = []

    async def inner(scope, receive, send) -> None:
        events.append(scope["type"])
    asyncio.run(RequestSizeLimitMiddleware(inner, 10)({"type": "lifespan"}, None, None))
    assert events == ["lifespan"]
