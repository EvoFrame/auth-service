"""Integration tests: M2M service token issuance and introspection."""

import uuid

import pytest
from argon2 import PasswordHasher
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from src.models.service_client import ServiceClient

pytestmark = pytest.mark.asyncio(loop_scope="session")
BASE = "/api/v1/service-clients"
_ph = PasswordHasher()


async def _seed_service_client(db_engine: AsyncEngine, service_id: str, secret: str) -> ServiceClient:
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        svc = ServiceClient(
            service_id=service_id,
            secret_hash=_ph.hash(secret),
            is_active=True,
        )
        session.add(svc)
        await session.commit()
        await session.refresh(svc)
        return svc


async def test_service_token_issuance(client: AsyncClient, db_engine: AsyncEngine):
    await _seed_service_client(db_engine, "test-svc", "svc-secret-1")
    resp = await client.post(
        f"{BASE}/token",
        json={"service_id": "test-svc", "service_secret": "svc-secret-1"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["access_token"]
    assert data["expires_in"] > 0


async def test_service_token_wrong_secret_returns_401(client: AsyncClient, db_engine: AsyncEngine):
    await _seed_service_client(db_engine, "test-svc-bad", "real-secret")
    resp = await client.post(
        f"{BASE}/token",
        json={"service_id": "test-svc-bad", "service_secret": "wrong-secret"},
    )
    assert resp.status_code == 401


async def test_service_token_unknown_service_returns_401(client: AsyncClient):
    resp = await client.post(
        f"{BASE}/token",
        json={"service_id": "ghost-svc", "service_secret": "any"},
    )
    assert resp.status_code == 401


async def test_service_introspect_valid_token(client: AsyncClient, db_engine: AsyncEngine):
    await _seed_service_client(db_engine, "test-svc-intro", "intro-secret")
    issue_resp = await client.post(
        f"{BASE}/token",
        json={"service_id": "test-svc-intro", "service_secret": "intro-secret"},
    )
    token = issue_resp.json()["access_token"]

    intro_resp = await client.post(f"{BASE}/introspect", json={"token": token})
    assert intro_resp.status_code == 200
    data = intro_resp.json()
    assert data["sub"] == "test-svc-intro"
    assert data["type"] == "service"
    assert data["scope"] == "internal"


async def test_service_introspect_invalid_token_returns_401(client: AsyncClient):
    resp = await client.post(f"{BASE}/introspect", json={"token": "not.a.token"})
    assert resp.status_code == 401


async def test_service_introspect_user_token_rejected(client: AsyncClient):
    """A user JWT must not pass service introspect."""
    from datetime import UTC, datetime, timedelta

    import jwt

    from src.config.settings import settings

    now = datetime.now(UTC)
    user_token = jwt.encode(
        {
            "jti": str(uuid.uuid4()),
            "sub": str(uuid.uuid4()),
            "email": "x@y.com",
            "roles": [],
            "type": "user",
            "iss": settings.SERVICE_ID,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=900)).timestamp()),
        },
        settings.RS256_PRIVATE_KEY,
        algorithm="RS256",
    )
    resp = await client.post(f"{BASE}/introspect", json={"token": user_token})
    assert resp.status_code == 401
