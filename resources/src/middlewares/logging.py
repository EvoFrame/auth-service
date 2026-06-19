import time

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = structlog.get_logger()

_MUTED_PATH_PREFIXES = ("/health", "/metrics")


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs each HTTP request with method, path, status, and duration."""

    async def dispatch(self, request: Request, call_next):
        """Log request details after the response is produced.

        Requests whose paths match a muted prefix (e.g. health probes and the
        metrics scrape endpoint) are silently passed through without logging.

        Args:
            request: The incoming HTTP request.
            call_next: The next middleware or route handler in the chain.

        Returns:
            The response from the downstream handler.
        """
        start = time.perf_counter()
        response = await call_next(request)

        if not request.url.path.startswith(_MUTED_PATH_PREFIXES):
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            logger.info(
                "http_request",
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=duration_ms,
                request_id=getattr(request.state, "request_id", None),
            )

        return response
