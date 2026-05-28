"""Nightly cleanup of expired and revoked refresh sessions."""

from datetime import UTC, datetime

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import delete

from src.db.session import AsyncSessionLocal
from src.models.session import RefreshSession

logger = structlog.get_logger()

_scheduler: AsyncIOScheduler | None = None


async def _cleanup_sessions() -> None:
    now = datetime.now(UTC)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            delete(RefreshSession).where((RefreshSession.expires_at < now) | (RefreshSession.revoked_at.isnot(None)))
        )
        await session.commit()
    logger.info("session_cleanup", deleted=result.rowcount)


def start_scheduler() -> AsyncIOScheduler:
    global _scheduler
    _scheduler = AsyncIOScheduler()
    _scheduler.add_job(_cleanup_sessions, "cron", hour=3, minute=0, id="session_cleanup")
    _scheduler.start()
    logger.info("scheduler_started")
    return _scheduler


def stop_scheduler() -> None:
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
