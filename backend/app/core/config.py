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
    max_request_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)
    rate_limit_requests: int = Field(default=120, ge=1, le=10_000)
    rate_limit_window_seconds: float = Field(default=60.0, gt=0, le=3600)
    max_concurrent_requests: int = Field(default=32, ge=1, le=1000)
    auth_tokens_file: str | None = None
    max_concurrent_agent_runs: int = Field(default=4, ge=1, le=32)
    admin_username: str | None = None
    admin_password: SecretStr | None = None
    admin_session_hours: int = Field(default=12, ge=1, le=168)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def split_cors_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("openai_api_key", "foundry_api_key", "ai_model", "ai_endpoint", "ai_temperature",
                     "incident_store_dir", "auth_tokens_file", "admin_username", "admin_password", mode="before")
    @classmethod
    def empty_key_to_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

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
