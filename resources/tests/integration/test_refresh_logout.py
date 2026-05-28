"""Integration tests: token rotation (refresh) and session revocation (logout)."""

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio(loop_scope="session")
BASE = "/api/v1/auth"


async def _register_and_login(client: AsyncClient, redis_client, email: str, password: str) -> dict:
    """Helper: register, verify email, login — returns token response."""
    reg = await client.post(f"{BASE}/register", json={"email": email, "password": password})
    user_id = reg.json()["user_id"]
    keys = await redis_client.keys("email_verify:*")
    token = None
    for key in keys:
        if await redis_client.get(key) == user_id:
            token = key.split("email_verify:")[1]
            break
    assert token, f"No verification token found for user {user_id}"
    await client.post(f"{BASE}/verify-email", json={"token": token})
    resp = await client.post(f"{BASE}/login", json={"email": email, "password": password})
    return resp.json()


@pytest.mark.asyncio
async def test_refresh_returns_new_tokens(client: AsyncClient, redis_client):
    tokens = await _register_and_login(client, redis_client, "refresh1@example.com", "RefreshPw1!")
    refresh_resp = await client.post(f"{BASE}/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh_resp.status_code == 200
    new_tokens = refresh_resp.json()
    assert new_tokens["access_token"] != tokens["access_token"]
    assert new_tokens["refresh_token"] != tokens["refresh_token"]


@pytest.mark.asyncio
async def test_refresh_token_cannot_be_reused(client: AsyncClient, redis_client):
    """Refresh tokens are single-use; replaying the old one must fail."""
    tokens = await _register_and_login(client, redis_client, "refresh2@example.com", "RefreshPw2!")
    old_refresh = tokens["refresh_token"]
    # Consume the refresh token
    await client.post(f"{BASE}/refresh", json={"refresh_token": old_refresh})
    # Replay old token — must be rejected
    replay_resp = await client.post(f"{BASE}/refresh", json={"refresh_token": old_refresh})
    assert replay_resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_invalidates_refresh_token(client: AsyncClient, redis_client):
    tokens = await _register_and_login(client, redis_client, "logout1@example.com", "LogoutPw1!")
    logout_resp = await client.post(f"{BASE}/logout", json={"refresh_token": tokens["refresh_token"]})
    assert logout_resp.status_code == 200
    # Trying to refresh after logout must fail
    refresh_resp = await client.post(f"{BASE}/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh_resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_with_invalid_token_returns_200(client: AsyncClient):
    """Logout is idempotent — unknown/malformed tokens still return 200."""
    resp = await client.post(f"{BASE}/logout", json={"refresh_token": "bad:token"})
    assert resp.status_code == 200
