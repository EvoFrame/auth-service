from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from src.db.session import AsyncSessionLocal
from src.redis.client import get_redis

health_router = APIRouter(tags=["Health"])


@health_router.get("/health/live")
async def liveness():
    """Return a simple OK response to indicate the process is running."""
    return {"status": "ok"}


@health_router.get("/health/ready")
async def readiness():
    """Check database and Redis connectivity to determine service readiness.

    Returns a 200 response when all checks pass, or 503 when any check fails.
    """
    checks: dict[str, str] = {}

    try:
        async with AsyncSessionLocal() as s:
            await s.execute(text("SELECT 1"))
        checks["db"] = "ok"
    except Exception:
        checks["db"] = "error"

    try:
        redis = await get_redis()
        await redis.ping()
        checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "error"

    healthy = all(v == "ok" for v in checks.values())
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={"status": "ready" if healthy else "degraded", "checks": checks},
    )
