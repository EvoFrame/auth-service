import httpx

from src.libs.service_token_cache import ServiceTokenCache


class S2SClient:
    """HTTP client that automatically attaches a valid service JWT."""

    def __init__(self, base_url: str, token_cache: ServiceTokenCache):
        self._base = base_url
        self._cache = token_cache

    async def get(self, path: str, **kwargs) -> httpx.Response:
        return await self._request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs) -> httpx.Response:
        return await self._request("POST", path, **kwargs)

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        token = await self._cache.get()
        headers = kwargs.pop("headers", {})
        headers["X-Service-Token"] = f"Bearer {token}"
        async with httpx.AsyncClient(base_url=self._base) as client:
            return await client.request(method, path, headers=headers, **kwargs)
