from datetime import datetime, timezone

from redis.asyncio import Redis

from src.config.settings import settings


class EventPublisher:
    def __init__(self, redis: Redis):
        self._redis = redis

    async def publish(
        self,
        stream: str,
        payload: dict[str, str],
        *,
        maxlen: int = 50_000,
        issuer_service: str | None = None,
        issued_to_service: str | None = None,
    ) -> None:
        envelope: dict[str, str] = {
            "source_service": settings.SERVICE_ID,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        if issuer_service:
            envelope["issuer_service"] = issuer_service
        if issued_to_service:
            envelope["issued_to_service"] = issued_to_service

        await self._redis.xadd(stream, envelope, maxlen=maxlen, approximate=True)
