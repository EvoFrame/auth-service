"""Integration tests: register, login, and token response shape."""

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio(loop_scope="session")
BASE = "/api/v1/users"


@pytest.mark.asyncio
async def test_register_creates_user(client: AsyncClient):
    resp = await client.post(f"{BASE}/register", json={"email": "alice@example.com", "password": "Secret123!"})
    assert resp.status_code == 201
    data = resp.json()
    assert "user_id" in data
    assert "message" in data


@pytest.mark.asyncio
async def test_register_duplicate_email_returns_409(client: AsyncClient):
    payload = {"email": "bob@example.com", "password": "Secret123!"}
    await client.post(f"{BASE}/register", json=payload)
    resp = await client.post(f"{BASE}/register", json=payload)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "EMAIL_TAKEN"


@pytest.mark.asyncio
async def test_login_unverified_returns_403(client: AsyncClient):
    await client.post(f"{BASE}/register", json={"email": "carol@example.com", "password": "Pass1234!"})
    resp = await client.post(f"{BASE}/login", json={"email": "carol@example.com", "password": "Pass1234!"})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "EMAIL_NOT_VERIFIED"


@pytest.mark.asyncio
async def test_login_after_email_verification(client: AsyncClient, redis_client):
    email = "dave@example.com"
    password = "SuperPass99!"
    reg = await client.post(f"{BASE}/register", json={"email": email, "password": password})
    user_id = reg.json()["user_id"]

    # Simulate email verification — fetch token for this specific user
    keys = await redis_client.keys("email_verify:*")
    token = None
    for key in keys:
        if await redis_client.get(key) == user_id:
            token = key.split("email_verify:")[1]
            break
    assert token, f"No verification token found for user {user_id}"

    verify_resp = await client.post(f"{BASE}/verify-email", json={"token": token})
    assert verify_resp.status_code == 200

    login_resp = await client.post(f"{BASE}/login", json={"email": email, "password": password})
    assert login_resp.status_code == 200
    data = login_resp.json()
    assert data["token_type"] == "bearer"
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["expires_in"] > 0


@pytest.mark.asyncio
async def test_login_wrong_password_returns_401(client: AsyncClient, redis_client):
    email = "eve@example.com"
    reg = await client.post(f"{BASE}/register", json={"email": email, "password": "Correct123!"})
    user_id = reg.json()["user_id"]
    keys = await redis_client.keys("email_verify:*")
    token = None
    for key in keys:
        if await redis_client.get(key) == user_id:
            token = key.split("email_verify:")[1]
            break
    assert token
    await client.post(f"{BASE}/verify-email", json={"token": token})

    resp = await client.post(f"{BASE}/login", json={"email": email, "password": "Wrong!"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "INVALID_CREDENTIALS"


@pytest.mark.asyncio
async def test_login_nonexistent_user_returns_401(client: AsyncClient):
    resp = await client.post(f"{BASE}/login", json={"email": "nobody@example.com", "password": "x"})
    assert resp.status_code == 401
