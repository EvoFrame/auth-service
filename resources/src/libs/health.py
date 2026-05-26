from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from src.db.session import AsyncSessionLocal
from src.redis.client import get_redis

health_router = APIRouter(tags=["health"])


@health_router.get("/health/live")
async def liveness():
    return {"status": "ok"}


@health_router.get("/health/ready")
async def readiness():
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
