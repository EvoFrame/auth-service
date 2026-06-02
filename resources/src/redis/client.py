from redis.asyncio import Redis, from_url

from src.config.settings import settings

_client: Redis | None = None


async def get_redis() -> Redis:
    """Return the singleton async Redis client, creating it on first call.

    Returns:
        The global Redis client instance with decode_responses enabled.
    """
    global _client
    if _client is None:
        _client = await from_url(settings.REDIS_URL, decode_responses=True)
    return _client
