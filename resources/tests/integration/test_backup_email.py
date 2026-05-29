"""Integration tests: backup email field on user accounts."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
import pytest_asyncio
from argon2 import PasswordHasher
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from src.config.settings import settings
from src.models.rbac import Permission, Role, RolePermission, UserRole
from src.models.user import User

pytestmark = pytest.mark.asyncio(loop_scope="session")

BASE_USERS = "/api/v1/users"
BASE_ME = "/api/v1/users/me"

_ph = PasswordHasher()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _token(user_id: uuid.UUID) -> dict[str, str]:
    now = datetime.now(UTC)
    payload = {
        "jti": str(uuid.uuid4()),
        "sub": str(user_id),
        "email": "test@test.local",
        "roles": [],
        "type": "user",
        "iss": settings.SERVICE_ID,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=900)).timestamp()),
    }
    return {"authorization": f"Bearer {jwt.encode(payload, settings.RS256_PRIVATE_KEY, algorithm='RS256')}"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session")
async def be_admin(db_engine) -> uuid.UUID:
    """User with users:read and users:write permissions for admin CRUD tests."""
    from sqlalchemy import select

    user_id = uuid.uuid4()

    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            id=user_id,
            email=f"be-admin-{user_id}@test.local",
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.flush()

        async def _get_or_create(name: str) -> Permission:
            result = await session.execute(select(Permission).where(Permission.name == name))
            perm = result.scalar_one_or_none()
            if not perm:
                perm = Permission(name=name, description="seed")
                session.add(perm)
                await session.flush()
            return perm

        read_perm = await _get_or_create("users:read")
        write_perm = await _get_or_create("users:write")

        role = Role(name=f"be-write-role-{user_id}")
        session.add(role)
        await session.flush()

        session.add(RolePermission(role_id=role.id, permission_id=read_perm.id))
        session.add(RolePermission(role_id=role.id, permission_id=write_perm.id))
        session.add(UserRole(user_id=user_id, role_id=role.id))
        await session.commit()

    return user_id


@pytest_asyncio.fixture(scope="session")
async def be_user(db_engine) -> tuple[uuid.UUID, str]:
    """Plain active user for self-update (/me) tests."""
    user_id = uuid.uuid4()
    email = f"be-user-{user_id}@example.com"

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
async def be_target(db_engine) -> tuple[uuid.UUID, str]:
    """Target user for admin backup-email management."""
    user_id = uuid.uuid4()
    email = f"be-target-{user_id}@example.com"

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


# ---------------------------------------------------------------------------
# Schema presence tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_response_has_backup_email_fields(client: AsyncClient, be_admin, be_target):
    user_id, _ = be_target
    resp = await client.get(f"{BASE_USERS}/{user_id}", headers=_token(be_admin))
    assert resp.status_code == 200
    data = resp.json()
    assert "backup_email" in data
    assert "backup_email_verified" in data
    assert data["backup_email"] is None
    assert data["backup_email_verified"] is False


# ---------------------------------------------------------------------------
# Self-update (/me) backup email
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_self_set_backup_email(client: AsyncClient, be_user):
    user_id, _ = be_user
    backup = f"backup-{user_id}@example.com"
    resp = await client.patch(BASE_ME, json={"backup_email": backup}, headers=_token(user_id))
    assert resp.status_code == 200
    data = resp.json()
    assert data["backup_email"] == backup
    assert data["backup_email_verified"] is False


@pytest.mark.asyncio
async def test_self_backup_email_not_verified_by_default(client: AsyncClient, be_user):
    """Verified flag must be False after user sets their own backup email."""
    user_id, _ = be_user
    resp = await client.get(BASE_ME, headers=_token(user_id))
    assert resp.status_code == 200
    assert resp.json()["backup_email_verified"] is False


@pytest.mark.asyncio
async def test_self_backup_email_same_as_primary_returns_409(client: AsyncClient, be_user):
    user_id, email = be_user
    resp = await client.patch(BASE_ME, json={"backup_email": email}, headers=_token(user_id))
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "BACKUP_EMAIL_SAME_AS_PRIMARY"


@pytest.mark.asyncio
async def test_self_backup_email_duplicate_returns_409(client: AsyncClient, db_engine, be_user):
    """Another user's backup email must not be reused."""
    other_id = uuid.uuid4()
    shared_backup = f"shared-backup-{uuid.uuid4()}@example.com"
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        other = User(
            id=other_id,
            email=f"other-be-{other_id}@test.local",
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
            backup_email=shared_backup,
        )
        session.add(other)
        await session.commit()

    user_id, _ = be_user
    resp = await client.patch(BASE_ME, json={"backup_email": shared_backup}, headers=_token(user_id))
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "BACKUP_EMAIL_TAKEN"


@pytest.mark.asyncio
async def test_self_changing_backup_email_resets_verified_flag(client: AsyncClient, db_engine, be_user):
    """Changing backup address must reset backup_email_verified to False."""
    user_id, _ = be_user

    # Force-set verified = True directly in DB
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = await session.get(User, user_id)
        user.backup_email_verified = True
        await session.commit()

    new_backup = f"new-backup-{uuid.uuid4()}@example.com"
    resp = await client.patch(BASE_ME, json={"backup_email": new_backup}, headers=_token(user_id))
    assert resp.status_code == 200
    assert resp.json()["backup_email_verified"] is False


# ---------------------------------------------------------------------------
# Admin update backup email
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_set_backup_email(client: AsyncClient, be_admin, be_target):
    user_id, _ = be_target
    backup = f"admin-set-backup-{user_id}@example.com"
    resp = await client.patch(
        f"{BASE_USERS}/{user_id}",
        json={"backup_email": backup},
        headers=_token(be_admin),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["backup_email"] == backup
    assert data["backup_email_verified"] is False


@pytest.mark.asyncio
async def test_admin_mark_backup_email_verified(client: AsyncClient, be_admin, be_target):
    user_id, _ = be_target
    resp = await client.patch(
        f"{BASE_USERS}/{user_id}",
        json={"backup_email_verified": True},
        headers=_token(be_admin),
    )
    assert resp.status_code == 200
    assert resp.json()["backup_email_verified"] is True


@pytest.mark.asyncio
async def test_admin_change_backup_email_resets_verified(client: AsyncClient, be_admin, be_target):
    """Changing backup address without explicit verified flag resets it to False."""
    user_id, _ = be_target
    new_backup = f"admin-changed-backup-{uuid.uuid4()}@example.com"
    resp = await client.patch(
        f"{BASE_USERS}/{user_id}",
        json={"backup_email": new_backup},
        headers=_token(be_admin),
    )
    assert resp.status_code == 200
    assert resp.json()["backup_email_verified"] is False


@pytest.mark.asyncio
async def test_admin_set_backup_email_and_verified_simultaneously(client: AsyncClient, be_admin, be_target):
    """Admin can set backup address and mark it verified in one request."""
    user_id, _ = be_target
    backup = f"admin-verified-{uuid.uuid4()}@example.com"
    resp = await client.patch(
        f"{BASE_USERS}/{user_id}",
        json={"backup_email": backup, "backup_email_verified": True},
        headers=_token(be_admin),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["backup_email"] == backup
    assert data["backup_email_verified"] is True


@pytest.mark.asyncio
async def test_admin_backup_email_same_as_primary_returns_409(client: AsyncClient, be_admin, be_target):
    user_id, email = be_target
    resp = await client.patch(
        f"{BASE_USERS}/{user_id}",
        json={"backup_email": email},
        headers=_token(be_admin),
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "BACKUP_EMAIL_SAME_AS_PRIMARY"
