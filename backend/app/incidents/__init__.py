from pathlib import Path

from app.core.config import Settings, get_settings
from app.incidents.errors import (
    IncidentConflictError,
    IncidentError,
    IncidentIntegrityError,
    IncidentNotFoundError,
    IncidentValidationError,
    InvalidTransitionError,
    UnauthorizedActionError,
)
from app.incidents.models import Actor, ActorKind, Incident, IncidentCreateRequest, IncidentFilter, LifecycleStatus
from app.incidents.repository import DEFAULT_STORE_DIR, IncidentRepository, JsonIncidentRepository
from app.incidents.service import IncidentService


def build_incident_service(settings: Settings | None = None) -> IncidentService:
    configured = (settings or get_settings()).incident_store_dir
    return IncidentService(JsonIncidentRepository(Path(configured) if configured else DEFAULT_STORE_DIR))


__all__ = [
    "Actor",
    "ActorKind",
    "Incident",
    "IncidentConflictError",
    "IncidentCreateRequest",
    "IncidentError",
    "IncidentFilter",
    "IncidentIntegrityError",
    "IncidentNotFoundError",
    "IncidentRepository",
    "IncidentService",
    "IncidentValidationError",
    "InvalidTransitionError",
    "JsonIncidentRepository",
    "LifecycleStatus",
    "UnauthorizedActionError",
    "build_incident_service",
]
