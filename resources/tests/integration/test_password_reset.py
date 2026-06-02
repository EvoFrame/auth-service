"""Integration tests: password reset flow."""

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio(loop_scope="session")

USERS_BASE = "/api/v1/users"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _register_and_verify(client: AsyncClient, redis_client, email: str, password: str) -> str:
    """Register, verify email, and return the user_id."""
    reg = await client.post(f"{USERS_BASE}/register", json={"email": email, "password": password})
    assert reg.status_code == 201
    user_id = reg.json()["user_id"]

    keys = await redis_client.keys("email_verify:*")
    token = None
    for key in keys:
        if await redis_client.get(key) == user_id:
            token = key.split("email_verify:")[1]
            break
    assert token, f"No verification token found for {email}"

    verify = await client.post(f"{USERS_BASE}/verify-email", json={"token": token})
    assert verify.status_code == 200
    return user_id


async def _get_reset_token(redis_client, user_id: str) -> str:
    """Retrieve the password reset token stored in Redis for a user."""
    keys = await redis_client.keys("pwd_reset:*")
    for key in keys:
        if await redis_client.get(key) == user_id:
            return key.split("pwd_reset:")[1]
    return ""


# ---------------------------------------------------------------------------
# Password reset request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_reset_request_existing_email(client: AsyncClient, redis_client):
    email = "pwd-reset-1@example.com"
    user_id = await _register_and_verify(client, redis_client, email, "OldPass1!")

    resp = await client.post(f"{USERS_BASE}/password-reset/request", json={"email": email})
    assert resp.status_code == 200
    assert "message" in resp.json()

    token = await _get_reset_token(redis_client, user_id)
    assert token, "Reset token should be stored in Redis"


@pytest.mark.asyncio
async def test_password_reset_request_nonexistent_email(client: AsyncClient):
    """Returns the same success message to prevent user enumeration."""
    resp = await client.post(
        f"{USERS_BASE}/password-reset/request",
        json={"email": "nobody-ever@example.com"},
    )
    assert resp.status_code == 200
    assert "message" in resp.json()


# ---------------------------------------------------------------------------
# Password reset confirm
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_reset_confirm_success(client: AsyncClient, redis_client):
    email = "pwd-reset-2@example.com"
    user_id = await _register_and_verify(client, redis_client, email, "OldPass1!")

    await client.post(f"{USERS_BASE}/password-reset/request", json={"email": email})
    token = await _get_reset_token(redis_client, user_id)
    assert token

    resp = await client.post(
        f"{USERS_BASE}/password-reset/confirm",
        json={"token": token, "new_password": "NewPass99!"},
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "Password reset successfully."


@pytest.mark.asyncio
async def test_password_reset_new_password_works_on_login(client: AsyncClient, redis_client):
    """After a reset, login with new password should succeed."""
    email = "pwd-reset-3@example.com"
    user_id = await _register_and_verify(client, redis_client, email, "OldPass1!")

    await client.post(f"{USERS_BASE}/password-reset/request", json={"email": email})
    token = await _get_reset_token(redis_client, user_id)

    await client.post(
        f"{USERS_BASE}/password-reset/confirm",
        json={"token": token, "new_password": "NewPass99!"},
    )

    login_resp = await client.post(f"{USERS_BASE}/login", json={"email": email, "password": "NewPass99!"})
    assert login_resp.status_code == 200
    assert login_resp.json()["access_token"]


@pytest.mark.asyncio
async def test_password_reset_old_password_rejected_after_reset(client: AsyncClient, redis_client):
    """After a reset, old password must no longer work."""
    email = "pwd-reset-4@example.com"
    user_id = await _register_and_verify(client, redis_client, email, "OldPass1!")

    await client.post(f"{USERS_BASE}/password-reset/request", json={"email": email})
    token = await _get_reset_token(redis_client, user_id)

    await client.post(
        f"{USERS_BASE}/password-reset/confirm",
        json={"token": token, "new_password": "NewPass99!"},
    )

    login_resp = await client.post(f"{USERS_BASE}/login", json={"email": email, "password": "OldPass1!"})
    assert login_resp.status_code == 401


@pytest.mark.asyncio
async def test_password_reset_token_can_only_be_used_once(client: AsyncClient, redis_client):
    """The reset token is deleted after first use — replay attack is rejected."""
    email = "pwd-reset-5@example.com"
    user_id = await _register_and_verify(client, redis_client, email, "OldPass1!")

    await client.post(f"{USERS_BASE}/password-reset/request", json={"email": email})
    token = await _get_reset_token(redis_client, user_id)

    await client.post(
        f"{USERS_BASE}/password-reset/confirm",
        json={"token": token, "new_password": "NewPass99!"},
    )

    # Second use of the same token
    resp = await client.post(
        f"{USERS_BASE}/password-reset/confirm",
        json={"token": token, "new_password": "AnotherPass1!"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_password_reset_invalid_token(client: AsyncClient):
    resp = await client.post(
        f"{USERS_BASE}/password-reset/confirm",
        json={"token": "not-a-real-token", "new_password": "NewPass99!"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_password_reset_revokes_refresh_sessions(client: AsyncClient, redis_client):
    """Active refresh sessions should be invalidated after a password reset."""
    email = "pwd-reset-6@example.com"
    user_id = await _register_and_verify(client, redis_client, email, "OldPass1!")

    # Login to create a refresh session
    login_resp = await client.post(f"{USERS_BASE}/login", json={"email": email, "password": "OldPass1!"})
    refresh_token = login_resp.json()["refresh_token"]

    # Request and confirm password reset
    await client.post(f"{USERS_BASE}/password-reset/request", json={"email": email})
    token = await _get_reset_token(redis_client, user_id)
    await client.post(
        f"{USERS_BASE}/password-reset/confirm",
        json={"token": token, "new_password": "NewPass99!"},
    )

    # Old refresh token should now be rejected
    refresh_resp = await client.post(f"{USERS_BASE}/refresh", json={"refresh_token": refresh_token})
    assert refresh_resp.status_code == 401
