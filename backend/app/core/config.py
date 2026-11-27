import ipaddress
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Network Incident Diagnosis Assistant"
    app_version: str = "0.1.0"
    environment: Literal["development", "staging", "production"] = "development"
    api_prefix: str = "/api/v1"
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    openai_api_key: SecretStr | None = Field(default=None, validation_alias=AliasChoices("ai_api_key", "openai_api_key"))
    foundry_api_key: SecretStr | None = None
    ai_provider: Literal["disabled", "openai", "foundry"] = "disabled"
    ai_model: str | None = None
    ai_endpoint: str | None = None
    ai_timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    ai_max_output_tokens: int = Field(default=2000, ge=256, le=16000)
    ai_temperature: float | None = Field(default=None, ge=0, le=2)
    incident_store_dir: str | None = None
    demo_incidents: bool = True  # seed the SCN synthetic scenarios as demo incident records at startup (idempotent)
    max_request_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)
    rate_limit_requests: int = Field(default=120, ge=1, le=10_000)
    rate_limit_window_seconds: float = Field(default=60.0, gt=0, le=3600)
    max_concurrent_requests: int = Field(default=32, ge=1, le=1000)
    auth_tokens_file: str | None = None
    auth_users_file: str | None = None
    max_concurrent_agent_runs: int = Field(default=4, ge=1, le=32)
    model_run_seconds: float = Field(default=120.0, ge=5, le=300)
    session_hours: int = Field(default=12, ge=1, le=168, validation_alias=AliasChoices("session_hours", "admin_session_hours"))
    login_max_failures: int = Field(default=5, ge=1, le=100)
    login_lockout_seconds: float = Field(default=300.0, ge=1, le=3600)
    # Observability. The simulator only produces data for scenarios someone is watching; the UDP receivers are off unless
    # a port is set, and bind to loopback unless a remote bind is explicitly allowed.
    conversation_store_dir: str | None = "var/conversations"  # empty value: keep conversations in memory only
    telemetry_simulation: bool = True
    telemetry_interval_seconds: float = Field(default=5.0, ge=0.1, le=300)
    telemetry_max_series: int = Field(default=2000, ge=10, le=100_000)
    telemetry_points_per_series: int = Field(default=720, ge=10, le=100_000)
    telemetry_max_events: int = Field(default=5000, ge=10, le=1_000_000)
    telemetry_max_flows: int = Field(default=20_000, ge=10, le=1_000_000)
    telemetry_syslog_udp_port: int = Field(default=0, ge=0, le=65535)
    telemetry_flow_udp_port: int = Field(default=0, ge=0, le=65535)
    telemetry_udp_host: str = "127.0.0.1"
    telemetry_udp_allow_remote: bool = False
    telemetry_udp_max_datagrams_per_second: int = Field(default=500, ge=1, le=100_000)
    telemetry_stream_max_seconds: float = Field(default=300.0, ge=1, le=3600)
    telemetry_max_streams: int = Field(default=8, ge=1, le=500)
    telemetry_max_streams_per_principal: int = Field(default=2, ge=1, le=20)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def split_cors_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("openai_api_key", "foundry_api_key", "ai_model", "ai_endpoint", "ai_temperature",
                     "incident_store_dir", "auth_tokens_file", "auth_users_file", "conversation_store_dir", mode="before")
    @classmethod
    def empty_key_to_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode="after")
    def keep_udp_receivers_local(self) -> "Settings":
        try:
            host = ipaddress.ip_address(self.telemetry_udp_host)
        except ValueError:
            raise ValueError("TELEMETRY_UDP_HOST must be an IP address") from None
        if not host.is_loopback and not self.telemetry_udp_allow_remote:
            raise ValueError("TELEMETRY_UDP_HOST is not a loopback address; set TELEMETRY_UDP_ALLOW_REMOTE=true to accept remote senders")
        return self

    @model_validator(mode="after")
    def reject_wildcard_origin_in_production(self) -> "Settings":
        if self.is_production and "*" in self.cors_origins:
            raise ValueError("Wildcard CORS origin is not allowed in production")
        return self

    @model_validator(mode="after")
    def require_complete_ai_configuration_in_production(self) -> "Settings":
        if not self.is_production or self.ai_provider == "disabled":
            return self
        key = self.openai_api_key if self.ai_provider == "openai" else self.foundry_api_key
        if not self.ai_model or key is None or (self.ai_provider == "foundry" and not self.ai_endpoint):
            raise ValueError("Production AI configuration requires a model, API key and, for foundry, an endpoint")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
