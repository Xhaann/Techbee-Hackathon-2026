from fastapi import APIRouter

from app.api.routes import agent, auth, conversations, dashboard, diagnosis, incidents, knowledge, reports, topology
from app.core.responses import ErrorResponse

api_router = APIRouter(
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    }
)

for module in (auth, dashboard, topology, diagnosis, agent, conversations, incidents, knowledge, reports):
    api_router.include_router(module.router)
