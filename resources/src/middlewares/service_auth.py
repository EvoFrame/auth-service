from datetime import timedelta

import jwt
import structlog
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from src.config.settings import settings

logger = structlog.get_logger()


class ServiceAuthMiddleware(BaseHTTPMiddleware):
    """Validates inbound X-Service-Token on routes that require it.

    Routes that don't require s2s auth should not have this middleware applied.
    Apply selectively via a sub-application or dependency instead if needed.
    """

    # Paths that bypass service token validation (health checks, public endpoints)
    _EXEMPT_PREFIXES = ("/health", "/docs", "/openapi", "/metrics", "/redoc")

    async def dispatch(self, request: Request, call_next):
        if any(request.url.path.startswith(p) for p in self._EXEMPT_PREFIXES):
            return await call_next(request)

        header = request.headers.get("X-Service-Token", "")
        if not header:
            return await call_next(request)

        if not header.startswith("Bearer "):
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
            return JSONResponse(status_code=403, content={"detail": "Service token expired"})
        except jwt.InvalidSignatureError:
            logger.error("service_token_invalid_signature", path=request.url.path)
            return JSONResponse(status_code=403, content={"detail": "Forbidden"})
        except jwt.InvalidTokenError:
            return JSONResponse(status_code=403, content={"detail": "Forbidden"})

        if payload.get("type") != "service" or payload.get("scope") != "internal":
            logger.warning("service_token_wrong_claims", claims=payload)
            return JSONResponse(status_code=403, content={"detail": "Forbidden"})

        request.state.caller_service = payload["sub"]
        return await call_next(request)
