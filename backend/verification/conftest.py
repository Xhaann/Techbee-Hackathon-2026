import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field

from app.core.config import Settings
from app.core.exceptions import AppError
from app.main import create_app


class SampleRequest(BaseModel):
    name: str = Field(min_length=1)
    count: int = Field(gt=0)


def build_test_router() -> APIRouter:
    router = APIRouter()

    @router.post("/test/validate")
    async def validate(payload: SampleRequest) -> SampleRequest:
        return payload

    @router.get("/test/app-error")
    async def app_error() -> None:
        raise AppError("Device not reachable", code="DEVICE_UNREACHABLE", status_code=409)

    @router.get("/test/crash")
    async def crash() -> None:
        raise RuntimeError("secret internal detail")

    return router


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None, openai_api_key="sk-test-not-a-real-key")


@pytest.fixture
def client(settings: Settings) -> TestClient:
    app = create_app(settings)
    app.include_router(build_test_router())
    return TestClient(app, raise_server_exceptions=False)
