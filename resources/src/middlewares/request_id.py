import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        """Attach a request ID to the request state, response headers, and log context.

        Uses the X-Request-ID header if provided, otherwise generates a UUID.

        Args:
            request: The incoming HTTP request.
            call_next: ASGI callable to forward the request to the next handler.

        Returns:
            The HTTP response with the X-Request-ID header set.
        """
        req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = req_id
        structlog.contextvars.bind_contextvars(request_id=req_id)
        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.clear_contextvars()
        response.headers["X-Request-ID"] = req_id
        return response
