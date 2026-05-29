"""Integration tests: JWT introspection endpoint."""

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from httpx import AsyncClient
from src.config.settings import settings

pytestmark = pytest.mark.asyncio(loop_scope="session")
BASE = "/api/v1/users"


def _make_token(payload_override: dict | None = None) -> str:
    now = datetime.now(UTC)
    payload = {
        "jti": "test-jti",
        "sub": "00000000-0000-0000-0000-000000000001",
        "email": "test@example.com",
        "roles": [],
        "type": "user",
        "iss": settings.SERVICE_ID,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=900)).timestamp()),
    }
    if payload_override:
        payload.update(payload_override)
    return jwt.encode(payload, settings.RS256_PRIVATE_KEY, algorithm="RS256")


@pytest.mark.asyncio
async def test_introspect_valid_token(client: AsyncClient):
    token = _make_token()
    resp = await client.get(f"{BASE}/introspect", headers={"authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["sub"] == "00000000-0000-0000-0000-000000000001"
    assert data["email"] == "test@example.com"
    assert data["type"] == "user"


@pytest.mark.asyncio
async def test_introspect_missing_header_returns_401(client: AsyncClient):
    resp = await client.get(f"{BASE}/introspect")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "MISSING_TOKEN"


@pytest.mark.asyncio
async def test_introspect_expired_token_returns_401(client: AsyncClient):
    token = _make_token(
        {
            "exp": int((datetime.now(UTC) - timedelta(seconds=1)).timestamp()),
        }
    )
    resp = await client.get(f"{BASE}/introspect", headers={"authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "TOKEN_EXPIRED"


@pytest.mark.asyncio
async def test_introspect_invalid_token_returns_401(client: AsyncClient):
    resp = await client.get(f"{BASE}/introspect", headers={"authorization": "Bearer not.a.jwt"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_introspect_service_token_rejected(client: AsyncClient):
    """A service-type JWT must not pass the user introspect endpoint."""
    now = datetime.now(UTC)
    payload = {
        "jti": "svc-jti",
        "sub": "some-service",
        "type": "service",
        "scope": "internal",
        "iss": settings.SERVICE_ID,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=300)).timestamp()),
    }
    token = jwt.encode(payload, settings.RS256_PRIVATE_KEY, algorithm="RS256")
    resp = await client.get(f"{BASE}/introspect", headers={"authorization": f"Bearer {token}"})
    assert resp.status_code == 401
