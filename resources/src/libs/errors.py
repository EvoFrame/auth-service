from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: str | None = None


class ErrorResponse(BaseModel):
    error: ErrorDetail


class AppError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400):
        """Initialize an application-level error with a machine-readable code.

        Args:
            code: Machine-readable error identifier (e.g. "USER_NOT_FOUND").
            message: Human-readable error description.
            status_code: HTTP status code to return (default: 400).
        """
        self.code = code
        self.message = message
        self.status_code = status_code


def register_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers on the FastAPI application.

    Handles AppError with structured JSON error responses and catches all
    unhandled exceptions with a generic 500 response.

    Args:
        app: The FastAPI application instance to register handlers on.
    """
    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception):
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected error occurred.",
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )
