from app.core.exceptions import AppError


class IncidentError(AppError):
    code = "INCIDENT_ERROR"
    status_code = 400

    def __init__(self, message: str) -> None:
        super().__init__(message, code=self.code, status_code=self.status_code)


class IncidentNotFoundError(IncidentError):
    code = "INCIDENT_NOT_FOUND"
    status_code = 404


class IncidentValidationError(IncidentError):
    code = "INCIDENT_VALIDATION_ERROR"
    status_code = 422


class InvalidTransitionError(IncidentError):
    code = "INVALID_STATUS_TRANSITION"
    status_code = 409


class IncidentConflictError(IncidentError):
    code = "INCIDENT_CONFLICT"
    status_code = 409


class UnauthorizedActionError(IncidentError):
    code = "ACTION_NOT_PERMITTED"
    status_code = 403


class IncidentIntegrityError(IncidentError):
    code = "INCIDENT_INTEGRITY_ERROR"
    status_code = 500
