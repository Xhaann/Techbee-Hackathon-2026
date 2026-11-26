import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from app.core.config import Settings

OPENAI_ENDPOINT = "https://api.openai.com/v1"
MAX_RESPONSE_BYTES = 1_000_000
MAX_CONTENT_CHARS = 60_000
MAX_ERROR_CHARS = 200
MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")

Transport = Callable[[str, dict[str, str], bytes, float], tuple[int, bytes]]


class ProviderErrorKind(str, Enum):
    CONFIGURATION = "configuration"
    TIMEOUT = "timeout"
    CONNECTION = "connection"
    HTTP = "http"
    MALFORMED = "malformed"
    TRUNCATED = "truncated"


class ProviderError(Exception):
    def __init__(self, kind: ProviderErrorKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


class ToolCallRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    arguments: str = Field(max_length=8000)


class ModelReply(BaseModel):
    model_config = ConfigDict(frozen=True)

    content: str | None
    tool_calls: list[ToolCallRequest]
    finish_reason: str | None


class ModelProvider(Protocol):
    name: str
    model: str

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None) -> ModelReply: ...


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    model: str
    endpoint: str
    api_key: SecretStr
    auth_header: str
    timeout_seconds: float
    max_output_tokens: int
    temperature: float | None


def require_https(endpoint: str) -> str:
    parts = urlsplit(endpoint)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise ProviderError(ProviderErrorKind.CONFIGURATION, "AI endpoint must be an https URL without credentials or query")
    return endpoint.rstrip("/")


def build_provider_config(settings: Settings) -> ProviderConfig:
    if settings.ai_provider == "disabled":
        raise ProviderError(ProviderErrorKind.CONFIGURATION, "AI provider is disabled")
    if not settings.ai_model or not MODEL_NAME.match(settings.ai_model):
        raise ProviderError(ProviderErrorKind.CONFIGURATION, "AI_MODEL must name an approved model")
    if settings.ai_provider == "openai":
        api_key, endpoint, header = settings.openai_api_key, settings.ai_endpoint or OPENAI_ENDPOINT, "Authorization"
    else:
        api_key, endpoint, header = settings.foundry_api_key, settings.ai_endpoint, "api-key"
        if not endpoint:
            raise ProviderError(ProviderErrorKind.CONFIGURATION, "AI_ENDPOINT is required for the foundry provider")
    if api_key is None:
        raise ProviderError(ProviderErrorKind.CONFIGURATION, f"API key for provider '{settings.ai_provider}' is not configured")
    return ProviderConfig(
        name=settings.ai_provider, model=settings.ai_model, endpoint=require_https(endpoint), api_key=api_key,
        auth_header=header, timeout_seconds=settings.ai_timeout_seconds,
        max_output_tokens=settings.ai_max_output_tokens, temperature=settings.ai_temperature,
    )


def urllib_transport(url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_RESPONSE_BYTES + 1)


class ChatFunction(BaseModel):
    name: str
    arguments: str


class ChatToolCall(BaseModel):
    id: str
    type: str = "function"
    function: ChatFunction


class ChatMessage(BaseModel):
    content: str | None = None
    tool_calls: list[ChatToolCall] | None = None


class ChatChoice(BaseModel):
    message: ChatMessage
    finish_reason: str | None = None


class ChatCompletion(BaseModel):
    choices: list[ChatChoice] = Field(min_length=1)


class ChatCompletionsProvider:
    def __init__(self, config: ProviderConfig, transport: Transport = urllib_transport) -> None:
        self.config = config
        self.transport = transport
        self.name = config.name
        self.model = config.model

    def scrub(self, text: str) -> str:
        return text.replace(self.config.api_key.get_secret_value(), "[redacted]")[:MAX_ERROR_CHARS]

    def headers(self) -> dict[str, str]:
        secret = self.config.api_key.get_secret_value()
        value = f"Bearer {secret}" if self.config.auth_header == "Authorization" else secret
        return {"Content-Type": "application/json", self.config.auth_header: value}

    def payload(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "max_completion_tokens": self.config.max_output_tokens,
        }
        if self.config.temperature is not None:
            payload["temperature"] = self.config.temperature
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        return payload

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None) -> ModelReply:
        body = json.dumps(self.payload(messages, tools)).encode("utf-8")
        try:
            status, raw = self.transport(f"{self.config.endpoint}/chat/completions", self.headers(), body,
                                         self.config.timeout_seconds)
        except TimeoutError:
            raise ProviderError(ProviderErrorKind.TIMEOUT, f"Provider did not respond within {self.config.timeout_seconds}s") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise ProviderError(ProviderErrorKind.TIMEOUT, f"Provider did not respond within {self.config.timeout_seconds}s") from None
            raise ProviderError(ProviderErrorKind.CONNECTION, "Provider connection failed") from None
        except OSError:
            raise ProviderError(ProviderErrorKind.CONNECTION, "Provider connection failed") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ProviderError(ProviderErrorKind.TRUNCATED, "Provider response exceeded the size limit")
        if status != 200:
            raise ProviderError(ProviderErrorKind.HTTP, f"Provider returned HTTP {status}: {self.error_message(raw)}")
        try:
            completion = ChatCompletion.model_validate_json(raw)
        except ValidationError:
            raise ProviderError(ProviderErrorKind.MALFORMED, "Provider response did not match the chat completion schema") from None
        choice = completion.choices[0]
        if choice.finish_reason == "length":
            raise ProviderError(ProviderErrorKind.TRUNCATED, "Model output reached the maximum output token limit")
        content = choice.message.content
        if content is not None and len(content) > MAX_CONTENT_CHARS:
            raise ProviderError(ProviderErrorKind.TRUNCATED, "Model output exceeded the content size limit")
        try:
            calls = [ToolCallRequest(id=call.id, name=call.function.name, arguments=call.function.arguments)
                     for call in choice.message.tool_calls or []]
        except ValidationError:
            raise ProviderError(ProviderErrorKind.MALFORMED, "Provider returned an invalid tool call") from None
        return ModelReply(content=content, tool_calls=calls, finish_reason=choice.finish_reason)

    def error_message(self, raw: bytes) -> str:
        try:
            message = json.loads(raw)["error"]["message"]
        except (ValueError, KeyError, TypeError):
            return "no error details"
        return self.scrub(str(message))


def build_provider(settings: Settings, transport: Transport = urllib_transport) -> ChatCompletionsProvider:
    return ChatCompletionsProvider(build_provider_config(settings), transport)
