from redis.asyncio import Redis, from_url

from src.config.settings import settings

_client: Redis | None = None


async def get_redis() -> Redis:
    global _client
    if _client is None:
        _client = await from_url(settings.REDIS_URL, decode_responses=True)
    return _client
