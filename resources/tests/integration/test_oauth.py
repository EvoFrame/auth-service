"""Integration tests: OAuth2 social login flow.

All external HTTP calls to OAuth providers are patched so tests are fully
self-contained.  We exercise the controller logic (DB interaction, error
paths) without hitting real provider endpoints.
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from argon2 import PasswordHasher
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.user import User

pytestmark = pytest.mark.asyncio(loop_scope="session")
BASE = "/api/v1/users/oauth"

_ph = PasswordHasher()


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


def _mock_oauth_client(email: str | None = "oauth-user@example.com") -> MagicMock:
    """Build a mock AsyncOAuth2Client that returns *email* from /userinfo."""
    userinfo_resp = MagicMock()
    userinfo_resp.raise_for_status = MagicMock()
    userinfo_resp.json.return_value = {"email": email, "sub": "12345", "name": "Test User"}

    client = AsyncMock()
    client.fetch_token = AsyncMock(return_value={"access_token": "fake-token"})
    client.get = AsyncMock(return_value=userinfo_resp)

    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=client)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


def _mock_github_client_private_email(primary_email: str) -> MagicMock:
    """GitHub user endpoint returns null email; /user/emails returns the real one."""
    user_resp = MagicMock()
    user_resp.raise_for_status = MagicMock()
    user_resp.json.return_value = {"email": None, "login": "gh-user"}  # private email

    emails_resp = MagicMock()
    emails_resp.raise_for_status = MagicMock()
    emails_resp.json.return_value = [
        {"email": "old@example.com", "primary": False, "verified": True},
        {"email": primary_email, "primary": True, "verified": True},
    ]

    call_count = {"n": 0}

    async def _get(url: str, **kwargs):
        call_count["n"] += 1
        if "emails" in url:
            return emails_resp
        return user_resp

    client = AsyncMock()
    client.fetch_token = AsyncMock(return_value={"access_token": "fake-token"})
    client.get = _get

    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=client)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


_PATCH = "src.controllers.oauth.AsyncOAuth2Client"
_SETTINGS_PATCH = "src.controllers.oauth.settings"

_FAKE_SETTINGS = {
    "GOOGLE_CLIENT_ID": "fake-google-id",
    "GOOGLE_CLIENT_SECRET": "fake-google-secret",
    "GITHUB_CLIENT_ID": "fake-github-id",
    "GITHUB_CLIENT_SECRET": "fake-github-secret",
    "OAUTH_REDIRECT_BASE_URL": "http://localhost:8080",
}


def _patched_settings():
    """MagicMock for settings with OAuth credentials and token TTL filled in."""
    from src.config.settings import settings as _real

    mock = MagicMock(wraps=_real)
    overrides = {
        **_FAKE_SETTINGS,
        "ACCESS_TOKEN_TTL": _real.ACCESS_TOKEN_TTL,
        "SERVICE_ID": _real.SERVICE_ID,
        "RS256_PRIVATE_KEY": _real.RS256_PRIVATE_KEY,
    }
    for key, value in overrides.items():
        setattr(mock, key, value)
    return mock


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session")
async def existing_oauth_user(db_engine) -> tuple[uuid.UUID, str]:
    """Pre-existing user that will be recognised on OAuth login."""
    user_id = uuid.uuid4()
    email = f"existing-oauth-{user_id}@example.com"
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            id=user_id,
            email=email,
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.commit()
    return user_id, email


@pytest_asyncio.fixture(scope="session")
async def disabled_oauth_user(db_engine) -> str:
    """Inactive user — OAuth login must be rejected."""
    email = f"disabled-oauth-{uuid.uuid4()}@example.com"
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            email=email,
            password_hash=_ph.hash("Password1!"),
            is_active=False,
            is_verified=True,
        )
        session.add(user)
        await session.commit()
    return email


@pytest_asyncio.fixture(scope="session")
async def deleted_oauth_user(db_engine) -> str:
    """Soft-deleted user — OAuth login must be rejected."""
    email = f"deleted-oauth-{uuid.uuid4()}@example.com"
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            email=email,
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
            deleted_at=datetime.now(UTC),
        )
        session.add(user)
        await session.commit()
    return email


# ---------------------------------------------------------------------------
# Unsupported / unconfigured provider
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oauth_unsupported_provider(client: AsyncClient):
    resp = await client.post(f"{BASE}/twitter?code=abc")
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "UNSUPPORTED_PROVIDER"


@pytest.mark.asyncio
async def test_oauth_provider_not_configured(client: AsyncClient):
    """Google/GitHub with empty credentials → 503."""
    with patch(_PATCH, return_value=_mock_oauth_client()):
        with patch("src.controllers.oauth.settings") as mock_settings:
            mock_settings.GOOGLE_CLIENT_ID = ""
            mock_settings.GOOGLE_CLIENT_SECRET = ""
            resp = await client.post(f"{BASE}/google?code=abc")
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "PROVIDER_NOT_CONFIGURED"


# ---------------------------------------------------------------------------
# New user auto-registration via OAuth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oauth_google_new_user_created(client: AsyncClient, db_engine):
    new_email = f"google-new-{uuid.uuid4()}@example.com"
    with patch(_PATCH, return_value=_mock_oauth_client(email=new_email)), patch(_SETTINGS_PATCH, _patched_settings()):
        resp = await client.post(f"{BASE}/google?code=auth-code-123")

    assert resp.status_code == 200
    data = resp.json()
    assert data["access_token"]
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0

    # Verify user was created in DB
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        from sqlalchemy import select

        user = (await session.execute(select(User).where(User.email == new_email))).scalar_one_or_none()
    assert user is not None
    assert user.is_verified is True
    assert user.is_active is True


@pytest.mark.asyncio
async def test_oauth_github_new_user_created(client: AsyncClient, db_engine):
    new_email = f"github-new-{uuid.uuid4()}@example.com"
    with patch(_PATCH, return_value=_mock_oauth_client(email=new_email)), patch(_SETTINGS_PATCH, _patched_settings()):
        resp = await client.post(f"{BASE}/github?code=gh-code-456")

    assert resp.status_code == 200
    assert resp.json()["access_token"]


# ---------------------------------------------------------------------------
# Existing user sign-in via OAuth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oauth_existing_user_signs_in(client: AsyncClient, existing_oauth_user):
    _, email = existing_oauth_user
    with patch(_PATCH, return_value=_mock_oauth_client(email=email)), patch(_SETTINGS_PATCH, _patched_settings()):
        resp = await client.post(f"{BASE}/google?code=code-returning-user")

    assert resp.status_code == 200
    assert resp.json()["access_token"]


# ---------------------------------------------------------------------------
# GitHub private email fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oauth_github_private_email_fallback(client: AsyncClient, db_engine):
    """When GitHub /user returns null email, controller fetches /user/emails."""
    private_email = f"github-private-{uuid.uuid4()}@example.com"
    with (
        patch(_PATCH, return_value=_mock_github_client_private_email(private_email)),
        patch(_SETTINGS_PATCH, _patched_settings()),
    ):
        resp = await client.post(f"{BASE}/github?code=private-email-code")

    assert resp.status_code == 200
    assert resp.json()["access_token"]

    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        from sqlalchemy import select

        user = (await session.execute(select(User).where(User.email == private_email))).scalar_one_or_none()
    assert user is not None


@pytest.mark.asyncio
async def test_oauth_github_no_verified_email_returns_400(client: AsyncClient):
    """If /user and /user/emails both yield no verified primary email → 400."""
    user_resp = MagicMock()
    user_resp.raise_for_status = MagicMock()
    user_resp.json.return_value = {"email": None}

    emails_resp = MagicMock()
    emails_resp.raise_for_status = MagicMock()
    emails_resp.json.return_value = [
        {"email": "unverified@example.com", "primary": True, "verified": False},
    ]

    async def _get(url: str, **kwargs):
        if "emails" in url:
            return emails_resp
        return user_resp

    client_mock = AsyncMock()
    client_mock.fetch_token = AsyncMock(return_value={"access_token": "t"})
    client_mock.get = _get

    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=client_mock)
    ctx.__aexit__ = AsyncMock(return_value=False)

    with patch(_PATCH, return_value=ctx), patch(_SETTINGS_PATCH, _patched_settings()):
        resp = await client.post(f"{BASE}/github?code=no-email-code")

    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "OAUTH_NO_EMAIL"


# ---------------------------------------------------------------------------
# Blocked accounts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oauth_disabled_user_returns_403(client: AsyncClient, disabled_oauth_user):
    with (
        patch(_PATCH, return_value=_mock_oauth_client(email=disabled_oauth_user)),
        patch(_SETTINGS_PATCH, _patched_settings()),
    ):
        resp = await client.post(f"{BASE}/google?code=disabled-code")

    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "ACCOUNT_DISABLED"


@pytest.mark.asyncio
async def test_oauth_deleted_user_returns_403(client: AsyncClient, deleted_oauth_user):
    with (
        patch(_PATCH, return_value=_mock_oauth_client(email=deleted_oauth_user)),
        patch(_SETTINGS_PATCH, _patched_settings()),
    ):
        resp = await client.post(f"{BASE}/google?code=deleted-code")

    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "ACCOUNT_DELETED"
