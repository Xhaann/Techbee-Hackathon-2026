from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.responses import ErrorBody, ErrorDetail, ErrorResponse
from app.security.secrets import redact


class AppError(Exception):
    def __init__(self, message: str, code: str = "APPLICATION_ERROR", status_code: int = 400,
                 headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.headers = headers


def error_response(
    status_code: int,
    code: str,
    message: str,
    details: list[ErrorDetail] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body = ErrorResponse(error=ErrorBody(code=code, message=redact(message)[:500], details=details))
    return JSONResponse(
        status_code=status_code,
        content=body.model_dump(exclude_none=True),
        headers=headers,
    )


def status_code_name(status_code: int) -> str:
    try:
        return HTTPStatus(status_code).name
    except ValueError:
        return "HTTP_ERROR"


async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
    return error_response(exc.status_code, exc.code, exc.message, headers=getattr(exc, "headers", None))


async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    message = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return error_response(exc.status_code, status_code_name(exc.status_code), message, headers=exc.headers)


async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    details = [
        ErrorDetail(
            field=".".join(str(part) for part in error["loc"]),
            message=error["msg"],
            type=error["type"],
        )
        for error in exc.errors()
    ]
    return error_response(422, "VALIDATION_ERROR", "Request validation failed", details)


async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    return error_response(500, "INTERNAL_SERVER_ERROR", "An unexpected error occurred")


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, handle_app_error)
    app.add_exception_handler(StarletteHTTPException, handle_http_exception)
    app.add_exception_handler(RequestValidationError, handle_validation_error)
    app.add_exception_handler(Exception, handle_unexpected_error)
