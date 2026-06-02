from datetime import timedelta

import jwt
import structlog
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from src.config.settings import settings
from src.events.publisher import EventPublisher

logger = structlog.get_logger()


class ServiceAuthMiddleware(BaseHTTPMiddleware):
    """Validates inbound X-Service-Token on routes that require it."""

    _EXEMPT_PREFIXES = (
        "/health",
        "/docs",
        "/openapi",
        "/metrics",
        "/redoc",
        "/api/v1/service-clients/token",
    )

    async def dispatch(self, request: Request, call_next):
        """Validate the X-Service-Token header on non-exempt routes.

        Exempt paths (health, docs, metrics, token endpoint) bypass validation.
        In debug mode with SKIP_SERVICE_AUTH=True, validation is also bypassed.

        Args:
            request: The incoming HTTP request.
            call_next: ASGI callable to forward the request to the next handler.

        Returns:
            The response from the next handler, or a 403 JSON error response.
        """
        if any(request.url.path.startswith(p) for p in self._EXEMPT_PREFIXES):
            return await call_next(request)

        if settings.DEBUG and settings.SKIP_SERVICE_AUTH:
            logger.warning("service_auth_bypassed", path=request.url.path)
            return await call_next(request)

        header = request.headers.get("X-Service-Token", "")
        if not header or not header.startswith("Bearer "):
            await self._emit_denied(request, "missing")
            return JSONResponse(status_code=403, content={"detail": "Forbidden"})

        raw_token = header.removeprefix("Bearer ")
        try:
            payload = jwt.decode(
                raw_token,
                settings.RS256_PUBLIC_KEY,
                algorithms=["RS256"],
                leeway=timedelta(seconds=10),
            )
        except jwt.ExpiredSignatureError:
            logger.warning("service_token_expired", path=request.url.path)
            await self._emit_denied(request, "expired")
            return JSONResponse(status_code=403, content={"detail": "Service token expired"})
        except jwt.InvalidSignatureError:
            logger.error("service_token_invalid_signature", path=request.url.path)
            await self._emit_denied(request, "invalid_signature")
            return JSONResponse(status_code=403, content={"detail": "Forbidden"})
        except jwt.InvalidTokenError:
            await self._emit_denied(request, "invalid")
            return JSONResponse(status_code=403, content={"detail": "Forbidden"})

        if payload.get("type") != "service" or payload.get("scope") != "internal":
            logger.warning("service_token_wrong_claims", claims=payload)
            await self._emit_denied(request, "wrong_type")
            return JSONResponse(status_code=403, content={"detail": "Forbidden"})

        request.state.caller_service = payload["sub"]
        return await call_next(request)

    async def _emit_denied(self, request: Request, reason: str) -> None:
        """Publish an access-denied event to the Redis Stream.

        Failures are swallowed so a broken Redis connection never blocks the
        auth denial response.

        Args:
            request: The denied HTTP request (used for IP and path metadata).
            reason: Short string describing the denial reason (e.g. "expired").
        """
        try:
            redis = request.app.state.redis
            publisher = EventPublisher(redis)
            await publisher.publish(
                "auth.access.denied",
                {
                    "ip": request.client.host if request.client else "unknown",
                    "endpoint": request.url.path,
                    "method": request.method,
                    "reason": reason,
                },
            )
        except Exception:
            logger.warning("service_auth_event_publish_failed", reason=reason)
