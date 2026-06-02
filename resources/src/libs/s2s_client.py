import httpx

from src.libs.service_token_cache import ServiceTokenCache


class S2SClient:
    """HTTP client that automatically attaches a valid service JWT."""

    def __init__(self, base_url: str, token_cache: ServiceTokenCache):
        self._base = base_url
        self._cache = token_cache

    async def get(self, path: str, **kwargs) -> httpx.Response:
        """Send a GET request with an injected service token header.

        Args:
            path: The URL path relative to the base URL.
            **kwargs: Additional arguments forwarded to httpx.

        Returns:
            The HTTP response.
        """
        return await self._request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs) -> httpx.Response:
        """Send a POST request with an injected service token header.

        Args:
            path: The URL path relative to the base URL.
            **kwargs: Additional arguments forwarded to httpx.

        Returns:
            The HTTP response.
        """
        return await self._request("POST", path, **kwargs)

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Execute an HTTP request after injecting the service JWT.

        Fetches a valid token from the cache and attaches it as the
        X-Service-Token header before dispatching the request.

        Args:
            method: HTTP method string (e.g. "GET", "POST").
            path: The URL path relative to the base URL.
            **kwargs: Additional arguments forwarded to httpx.

        Returns:
            The HTTP response.
        """
        token = await self._cache.get()
        headers = kwargs.pop("headers", {})
        headers["X-Service-Token"] = f"Bearer {token}"
        async with httpx.AsyncClient(base_url=self._base) as client:
            return await client.request(method, path, headers=headers, **kwargs)
