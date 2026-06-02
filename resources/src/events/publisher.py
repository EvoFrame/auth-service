from datetime import UTC, datetime

from redis.asyncio import Redis

from src.config.settings import settings


class EventPublisher:
    """Publishes domain events to Redis Streams."""

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
        """Append an event envelope to a Redis Stream.

        Wraps the payload with standard metadata (source_service, timestamp)
        before writing to the stream.

        Args:
            stream: The Redis Stream key to publish to.
            payload: Arbitrary event data as string key-value pairs.
            maxlen: Maximum stream length; older entries are trimmed (default: 50,000).
            issuer_service: Optional service that issued a token (for auth events).
            issued_to_service: Optional service that received a token (for auth events).
        """
        envelope: dict[str, str] = {
            "source_service": settings.SERVICE_ID,
            "timestamp": datetime.now(UTC).isoformat(),
            **payload,
        }
        if issuer_service:
            envelope["issuer_service"] = issuer_service
        if issued_to_service:
            envelope["issued_to_service"] = issued_to_service

        await self._redis.xadd(stream, envelope, maxlen=maxlen, approximate=True)
