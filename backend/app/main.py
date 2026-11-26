from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.dependencies import Services
from app.api.router import api_router
from app.api.routes import health
from app.core.config import Settings, get_settings
from app.core.exceptions import register_exception_handlers
from app.security.api import (
    ConcurrencyLimiter,
    ConcurrencyLimitMiddleware,
    RateLimiter,
    RateLimitMiddleware,
    RequestIdMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    await app.state.services.agent.start()
    try:
        yield
    finally:
        app.state.services.shutdown_conversations()
        await app.state.services.agent.close()


def create_app(settings: Settings) -> FastAPI:
    docs_enabled = not settings.is_production
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )

    app.add_middleware(ConcurrencyLimitMiddleware, limiter=ConcurrencyLimiter(settings.max_concurrent_requests))
    app.add_middleware(RateLimitMiddleware, limiter=RateLimiter(settings.rate_limit_requests, settings.rate_limit_window_seconds))
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    # Outside the limiters so browsers can read their 413/429/503 responses.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Retry-After"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIdMiddleware)

    app.state.services = Services(settings)
    register_exception_handlers(app)
    app.include_router(health.router)
    app.include_router(api_router, prefix=settings.api_prefix)
    return app


app = create_app(get_settings())
