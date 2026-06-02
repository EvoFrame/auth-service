import asyncio
import time

import httpx
import structlog
from redis.asyncio import Redis

from src.config.settings import settings

logger = structlog.get_logger()

CACHE_KEY = "svc_token:{service_id}"
LOCK_KEY = "svc_token_lock:{service_id}"
LOCK_TTL = 15  # seconds — lock expires if holder crashes
BUFFER = 60  # refresh this many seconds before actual expiry


class ServiceTokenCache:
    """Distributed Redis-backed cache for the service's own M2M JWT.

    Uses a distributed lock so only one replica fetches a new token at a time,
    preventing a thundering herd on auth-service during startup.
    """

    def __init__(self, redis: Redis):
        self._redis = redis
        self._local_token: str | None = None
        self._local_expires_at: float = 0.0

    async def get(self) -> str:
        """Return a valid service JWT, using the local or Redis cache if possible.

        Checks the in-process cache first, then Redis. Falls back to fetching
        a fresh token from the auth-service if none is cached.

        Returns:
            A valid service JWT string.
        """
        if self._local_token and time.time() < self._local_expires_at - BUFFER:
            return self._local_token

        cache_key = CACHE_KEY.format(service_id=settings.SERVICE_ID)
        cached = await self._redis.get(cache_key)
        if cached:
            ttl = await self._redis.ttl(cache_key)
            self._local_token = cached
            self._local_expires_at = time.time() + ttl + BUFFER
            return self._local_token

        return await self._refresh()

    async def _refresh(self) -> str:
        """Acquire a distributed lock and fetch a fresh token from auth-service.

        Uses a Redis lock to ensure only one replica requests a new token at a time.
        If the lock cannot be acquired, waits briefly and checks if another replica
        has already populated the cache.

        Returns:
            A freshly issued service JWT string.
        """
        cache_key = CACHE_KEY.format(service_id=settings.SERVICE_ID)
        lock_key = LOCK_KEY.format(service_id=settings.SERVICE_ID)

        acquired = await self._redis.set(lock_key, "1", nx=True, ex=LOCK_TTL)

        if not acquired:
            await asyncio.sleep(0.5)
            cached = await self._redis.get(cache_key)
            if cached:
                ttl = await self._redis.ttl(cache_key)
                self._local_token = cached
                self._local_expires_at = time.time() + ttl + BUFFER
                return self._local_token
            return await self.get()

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{settings.AUTH_SERVICE_URL}/auth/service/token",
                    json={
                        "service_id": settings.SERVICE_ID,
                        "service_secret": settings.SERVICE_SECRET,
                    },
                )
                resp.raise_for_status()
                data = resp.json()

            token = data["access_token"]
            expires_in = data["expires_in"]

            await self._redis.setex(cache_key, expires_in - BUFFER, token)
            self._local_token = token
            self._local_expires_at = time.time() + expires_in
            return token
        finally:
            await self._redis.delete(lock_key)
