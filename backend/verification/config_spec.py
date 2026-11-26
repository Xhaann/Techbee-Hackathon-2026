import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.main import create_app

SECRET = "sk-test-not-a-real-key"


def test_defaults_without_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("ENVIRONMENT", "CORS_ORIGINS", "OPENAI_API_KEY", "API_PREFIX"):
        monkeypatch.delenv(name, raising=False)
    settings = Settings(_env_file=None)
    assert settings.environment == "development"
    assert settings.api_prefix == "/api/v1"
    assert settings.cors_origins == ["http://localhost:3000", "http://127.0.0.1:3000"]
    assert settings.openai_api_key is None


def test_values_loaded_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.setenv("CORS_ORIGINS", "https://a.example, https://b.example")
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    settings = Settings(_env_file=None)
    assert settings.environment == "staging"
    assert settings.cors_origins == ["https://a.example", "https://b.example"]
    assert settings.openai_api_key.get_secret_value() == SECRET


def test_empty_api_key_is_treated_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "")
    assert Settings(_env_file=None).openai_api_key is None


def test_invalid_environment_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, environment="local")


def test_wildcard_cors_rejected_in_production() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, environment="production", cors_origins="*")


def test_api_key_is_masked(settings: Settings) -> None:
    assert SECRET not in repr(settings)
    assert SECRET not in str(settings.model_dump())


def test_secrets_not_exposed_through_api(client: TestClient) -> None:
    for path in ("/health", "/openapi.json", "/docs", "/missing"):
        assert SECRET not in client.get(path).text


def test_docs_disabled_in_production() -> None:
    client = TestClient(create_app(Settings(_env_file=None, environment="production")))
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404
    assert client.get("/health").json() == {"status": "healthy"}
