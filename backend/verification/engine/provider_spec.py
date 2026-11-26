import json
import urllib.error

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.engine.providers import (
    OPENAI_ENDPOINT,
    ChatCompletionsProvider,
    ProviderError,
    ProviderErrorKind,
    build_provider,
    build_provider_config,
)
from verification.engine.helpers import FAKE_KEY, FakeTransport, ai_settings, completion

MESSAGES = [{"role": "user", "content": "hello"}]


def provider(transport: FakeTransport, **overrides: object) -> ChatCompletionsProvider:
    return build_provider(ai_settings(**overrides), transport)


def test_ai_settings_defaults_are_safe() -> None:
    settings = Settings(_env_file=None)
    assert settings.ai_provider == "disabled" and settings.ai_model is None
    assert settings.ai_timeout_seconds == 30.0 and settings.ai_max_output_tokens == 2000
    assert settings.ai_temperature is None


def test_ai_settings_are_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    for overrides in ({"ai_provider": "unsupported"}, {"ai_timeout_seconds": 0}, {"ai_timeout_seconds": 500},
                      {"ai_max_output_tokens": 10}, {"ai_temperature": 3}):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, **overrides)
    monkeypatch.setenv("AI_MODEL", "")
    monkeypatch.setenv("FOUNDRY_API_KEY", "")
    monkeypatch.setenv("AI_TEMPERATURE", "")
    settings = Settings(_env_file=None)
    assert settings.ai_model is None and settings.foundry_api_key is None and settings.ai_temperature is None


@pytest.mark.parametrize("overrides, message", [
    ({"ai_provider": "disabled"}, "disabled"),
    ({"ai_model": None}, "AI_MODEL"),
    ({"ai_model": "model; rm -rf /"}, "AI_MODEL"),
    ({"openai_api_key": None}, "API key"),
    ({"ai_provider": "foundry", "foundry_api_key": FAKE_KEY}, "AI_ENDPOINT"),
    ({"ai_endpoint": "http://api.example.com/v1"}, "https"),
    ({"ai_endpoint": "https://user:pass@api.example.com/v1"}, "https"),
    ({"ai_endpoint": "https://api.example.com/v1?key=abc"}, "https"),
])
def test_invalid_provider_configuration(overrides: dict, message: str) -> None:
    with pytest.raises(ProviderError) as error:
        build_provider_config(ai_settings(**overrides))
    assert error.value.kind == ProviderErrorKind.CONFIGURATION and message in error.value.message
    assert FAKE_KEY not in error.value.message


def test_openai_request_format() -> None:
    transport = FakeTransport(body=completion("done"))
    reply = provider(transport, ai_temperature=0.2, ai_max_output_tokens=512).complete(MESSAGES, [{"type": "function"}])
    assert reply.content == "done" and reply.tool_calls == []
    request = transport.requests[0]
    assert request["url"] == f"{OPENAI_ENDPOINT}/chat/completions"
    assert request["headers"]["Authorization"] == f"Bearer {FAKE_KEY}"
    assert request["timeout"] == 30.0
    payload = request["payload"]
    assert payload["model"] == "approved-test-model" and payload["max_completion_tokens"] == 512
    assert payload["temperature"] == 0.2 and payload["tool_choice"] == "auto" and payload["messages"] == MESSAGES


def test_foundry_request_format_and_optional_fields() -> None:
    transport = FakeTransport(body=completion("ok"))
    foundry = provider(transport, ai_provider="foundry", foundry_api_key=FAKE_KEY, openai_api_key=None,
                       ai_endpoint="https://example-resource.openai.azure.com/openai/v1/")
    foundry.complete(MESSAGES, None)
    request = transport.requests[0]
    assert request["url"] == "https://example-resource.openai.azure.com/openai/v1/chat/completions"
    assert request["headers"]["api-key"] == FAKE_KEY and "Authorization" not in request["headers"]
    assert "temperature" not in request["payload"] and "tools" not in request["payload"]
    assert foundry.name == "foundry" and foundry.model == "approved-test-model"


def test_tool_calls_are_parsed() -> None:
    calls = [{"id": "c1", "type": "function", "function": {"name": "get_topology", "arguments": "{\"site_id\": \"NYC\"}"}}]
    reply = provider(FakeTransport(body=completion(None, calls, "tool_calls"))).complete(MESSAGES, None)
    assert [(call.id, call.name, json.loads(call.arguments)) for call in reply.tool_calls] == [("c1", "get_topology", {"site_id": "NYC"})]


@pytest.mark.parametrize("error, kind", [
    (TimeoutError(), ProviderErrorKind.TIMEOUT),
    (urllib.error.URLError(TimeoutError()), ProviderErrorKind.TIMEOUT),
    (urllib.error.URLError("refused"), ProviderErrorKind.CONNECTION),
    (ConnectionResetError(), ProviderErrorKind.CONNECTION),
])
def test_transport_failures(error: Exception, kind: ProviderErrorKind) -> None:
    with pytest.raises(ProviderError) as raised:
        provider(FakeTransport(error=error)).complete(MESSAGES, None)
    assert raised.value.kind == kind


def test_http_error_is_reported_without_secret() -> None:
    body = {"error": {"message": f"Incorrect API key provided: {FAKE_KEY}"}}
    with pytest.raises(ProviderError) as raised:
        provider(FakeTransport(status=401, body=body)).complete(MESSAGES, None)
    assert raised.value.kind == ProviderErrorKind.HTTP and "HTTP 401" in raised.value.message
    assert FAKE_KEY not in raised.value.message and "[redacted]" in raised.value.message
    with pytest.raises(ProviderError) as raised:
        provider(FakeTransport(status=500, body=b"<html>oops</html>")).complete(MESSAGES, None)
    assert raised.value.message.endswith("no error details")


@pytest.mark.parametrize("body", [b"not json", {"choices": []}, {"choices": [{"message": {"content": 5}}]},
                                  {"choices": [{"message": {"tool_calls": [{"id": "x", "function": {"name": "a"}}]}}]},
                                  {"unexpected": True}])
def test_malformed_responses(body: object) -> None:
    with pytest.raises(ProviderError) as raised:
        provider(FakeTransport(body=body)).complete(MESSAGES, None)
    assert raised.value.kind == ProviderErrorKind.MALFORMED


def test_output_limits() -> None:
    with pytest.raises(ProviderError) as raised:
        provider(FakeTransport(body=completion("partial", finish_reason="length"))).complete(MESSAGES, None)
    assert raised.value.kind == ProviderErrorKind.TRUNCATED
    with pytest.raises(ProviderError) as raised:
        provider(FakeTransport(body=completion("x" * 70_000))).complete(MESSAGES, None)
    assert raised.value.kind == ProviderErrorKind.TRUNCATED
    with pytest.raises(ProviderError) as raised:
        provider(FakeTransport(body=b"x" * 1_000_001)).complete(MESSAGES, None)
    assert raised.value.kind == ProviderErrorKind.TRUNCATED


def test_secret_not_exposed_in_provider_repr() -> None:
    config = build_provider_config(ai_settings())
    assert FAKE_KEY not in repr(config) and FAKE_KEY not in str(config)
