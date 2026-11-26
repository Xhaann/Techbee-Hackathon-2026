from fastapi.testclient import TestClient

PREFLIGHT_HEADERS = {"Access-Control-Request-Method": "GET"}


def test_allowed_origin_receives_cors_headers(client: TestClient) -> None:
    response = client.options("/health", headers={"Origin": "http://localhost:3000", **PREFLIGHT_HEADERS})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_disallowed_origin_is_rejected(client: TestClient) -> None:
    response = client.options("/health", headers={"Origin": "http://evil.example", **PREFLIGHT_HEADERS})
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_simple_request_from_disallowed_origin_has_no_cors_header(client: TestClient) -> None:
    response = client.get("/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in response.headers


def test_limit_responses_carry_cors_headers_for_browser_clients() -> None:
    from app.core.config import Settings
    from app.main import create_app
    origin = {"Origin": "http://localhost:3000"}
    client = TestClient(create_app(Settings(_env_file=None, rate_limit_requests=1, max_request_bytes=1024)))
    oversized = client.post("/api/v1/incidents", content=b"x" * 2048, headers=origin | {"content-type": "application/json"})
    assert oversized.status_code == 413 and oversized.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert client.get("/health", headers=origin).status_code == 200
    limited = client.get("/health", headers=origin)
    assert limited.status_code == 429 and limited.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "retry-after" in limited.headers["access-control-expose-headers"].lower()


def test_preflight_is_answered_before_rate_limiting() -> None:
    from app.core.config import Settings
    from app.main import create_app
    client = TestClient(create_app(Settings(_env_file=None, rate_limit_requests=1)))
    preflight = {"Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST",
                 "Access-Control-Request-Headers": "authorization,content-type"}
    assert [client.options("/api/v1/incidents", headers=preflight).status_code for _ in range(3)] == [200, 200, 200]
    assert client.get("/health").status_code == 200
