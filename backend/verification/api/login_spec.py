from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app

API = "/api/v1"


def client(tmp_path, **overrides) -> TestClient:
    values = {"admin_username": "Admin", "admin_password": "admin123321", "auth_tokens_file": str(tmp_path / "tokens.json")}
    return TestClient(create_app(Settings(_env_file=None, **(values | overrides))))


def test_login_issues_a_working_manager_token(tmp_path) -> None:
    api = client(tmp_path)
    response = api.post(f"{API}/auth/login", json={"username": "Admin", "password": "admin123321"})
    assert response.status_code == 200
    body = response.json()
    assert body["principal"]["subject"] == "admin" and "close_reopen_incidents" in body["principal"]["permissions"]
    verified = api.post(f"{API}/auth/verify", headers={"Authorization": f"Bearer {body['token']}"})
    assert verified.status_code == 200 and verified.json()["subject"] == "admin"


def test_login_rejects_wrong_credentials(tmp_path) -> None:
    api = client(tmp_path)
    for username, password in (("Admin", "wrong"), ("admin", "admin123321"), ("someone", "admin123321")):
        response = api.post(f"{API}/auth/login", json={"username": username, "password": password})
        assert response.status_code == 401
        assert "admin123321" not in response.text
    assert not (tmp_path / "tokens.json").exists()


def test_login_unconfigured_returns_503(tmp_path) -> None:
    api = client(tmp_path, admin_password=None)
    assert api.post(f"{API}/auth/login", json={"username": "Admin", "password": "x"}).status_code == 503


def test_login_rejects_unknown_fields(tmp_path) -> None:
    api = client(tmp_path)
    response = api.post(f"{API}/auth/login", json={"username": "Admin", "password": "admin123321", "role": "x"})
    assert response.status_code == 422
