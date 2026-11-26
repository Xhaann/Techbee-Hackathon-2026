from fastapi.testclient import TestClient


def test_unknown_route_returns_standard_error(client: TestClient) -> None:
    response = client.get("/missing")
    assert response.status_code == 404
    assert response.json() == {"error": {"code": "NOT_FOUND", "message": "Not Found"}}


def test_method_not_allowed_returns_standard_error(client: TestClient) -> None:
    response = client.post("/health")
    assert response.status_code == 405
    assert response.json()["error"]["code"] == "METHOD_NOT_ALLOWED"
    assert response.headers["allow"] == "GET"


def test_invalid_payload_returns_validation_error(client: TestClient) -> None:
    response = client.post("/test/validate", json={"name": "", "count": "abc"})
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert {detail["field"] for detail in error["details"]} == {"body.name", "body.count"}
    assert all(set(detail) == {"field", "message", "type"} for detail in error["details"])


def test_missing_fields_return_validation_error(client: TestClient) -> None:
    response = client.post("/test/validate", json={})
    assert response.status_code == 422
    types = {detail["type"] for detail in response.json()["error"]["details"]}
    assert types == {"missing"}


def test_malformed_json_returns_validation_error(client: TestClient) -> None:
    response = client.post(
        "/test/validate",
        content='{"name": "router-1",',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["type"] == "json_invalid"


def test_valid_payload_is_accepted(client: TestClient) -> None:
    response = client.post("/test/validate", json={"name": "router-1", "count": 2})
    assert response.status_code == 200
    assert response.json() == {"name": "router-1", "count": 2}


def test_app_error_returns_standard_error(client: TestClient) -> None:
    response = client.get("/test/app-error")
    assert response.status_code == 409
    assert response.json() == {
        "error": {"code": "DEVICE_UNREACHABLE", "message": "Device not reachable"}
    }


def test_unexpected_error_hides_internal_details(client: TestClient) -> None:
    response = client.get("/test/crash")
    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "INTERNAL_SERVER_ERROR", "message": "An unexpected error occurred"}
    }
    assert "secret internal detail" not in response.text
    assert "Traceback" not in response.text
