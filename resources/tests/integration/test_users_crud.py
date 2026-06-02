"""Integration tests: admin user CRUD endpoints."""

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
BASE = "/api/v1/users"

_ph = PasswordHasher()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _token(user_id: uuid.UUID) -> dict[str, str]:
    now = datetime.now(UTC)
    payload = {
        "jti": str(uuid.uuid4()),
        "sub": str(user_id),
        "email": "admin@test.local",
        "roles": [],
        "type": "user",
        "iss": settings.SERVICE_ID,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=900)).timestamp()),
    }
    return {"authorization": f"Bearer {jwt.encode(payload, settings.RS256_PRIVATE_KEY, algorithm='RS256')}"}


# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session")
async def users_admin(db_engine) -> uuid.UUID:
    """User with users:read and users:write permissions."""
    from sqlalchemy import select

    user_id = uuid.uuid4()

    async def _get_or_create_perm(session: AsyncSession, name: str) -> Permission:
        result = await session.execute(select(Permission).where(Permission.name == name))
        perm = result.scalar_one_or_none()
        if not perm:
            perm = Permission(name=name, description="seed")
            session.add(perm)
            await session.flush()
        return perm

    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            id=user_id,
            email=f"users-admin-{user_id}@test.local",
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.flush()

        read_perm = await _get_or_create_perm(session, "users:read")
        write_perm = await _get_or_create_perm(session, "users:write")

        role = Role(name=f"users-admin-role-{user_id}")
        session.add(role)
        await session.flush()

        session.add(RolePermission(role_id=role.id, permission_id=read_perm.id))
        session.add(RolePermission(role_id=role.id, permission_id=write_perm.id))
        session.add(UserRole(user_id=user_id, role_id=role.id))
        await session.commit()

    return user_id


@pytest_asyncio.fixture(scope="session")
async def users_readonly(db_engine, users_admin) -> uuid.UUID:
    """User with users:read only."""
    from sqlalchemy import select

    user_id = uuid.uuid4()

    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            id=user_id,
            email=f"users-readonly-{user_id}@test.local",
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.flush()

        read_perm = (await session.execute(select(Permission).where(Permission.name == "users:read"))).scalar_one()

        role = Role(name=f"users-readonly-role-{user_id}")
        session.add(role)
        await session.flush()

        session.add(RolePermission(role_id=role.id, permission_id=read_perm.id))
        session.add(UserRole(user_id=user_id, role_id=role.id))
        await session.commit()

    return user_id


@pytest_asyncio.fixture(scope="session")
async def target_user(db_engine) -> tuple[uuid.UUID, str]:
    """A plain user to be managed by admin in CRUD tests."""
    user_id = uuid.uuid4()
    email = f"target-user-{user_id}@test.local"

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
# Auth guard tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_users_requires_auth(client: AsyncClient):
    resp = await client.get(BASE)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_user_requires_auth(client: AsyncClient, target_user):
    user_id, _ = target_user
    resp = await client.get(f"{BASE}/{user_id}")
    assert resp.status_code == 401


@pytest_asyncio.fixture(scope="session")
async def unprivileged_user(db_engine) -> uuid.UUID:
    """User with no permissions."""
    user_id = uuid.uuid4()
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            id=user_id,
            email=f"unprivileged-{user_id}@test.local",
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.commit()
    return user_id


@pytest.mark.asyncio
async def test_list_users_requires_read_permission(client: AsyncClient, unprivileged_user):
    resp = await client.get(BASE, headers=_token(unprivileged_user))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_update_user_requires_write_permission(client: AsyncClient, users_readonly, target_user):
    user_id, _ = target_user
    resp = await client.patch(
        f"{BASE}/{user_id}",
        json={"is_active": False},
        headers=_token(users_readonly),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_delete_user_requires_write_permission(client: AsyncClient, users_readonly, target_user):
    user_id, _ = target_user
    resp = await client.delete(f"{BASE}/{user_id}", headers=_token(users_readonly))
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_users(client: AsyncClient, users_admin, target_user):
    user_id, email = target_user
    resp = await client.get(f"{BASE}?page_size=100", headers=_token(users_admin))
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1
    emails = [u["email"] for u in data["items"]]
    assert email in emails


@pytest.mark.asyncio
async def test_list_users_pagination(client: AsyncClient, users_admin):
    resp = await client.get(f"{BASE}?page=1&page_size=1", headers=_token(users_admin))
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 1
    assert data["pages"] >= 1


@pytest.mark.asyncio
async def test_list_users_readonly_can_access(client: AsyncClient, users_readonly):
    resp = await client.get(BASE, headers=_token(users_readonly))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Get
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_user(client: AsyncClient, users_admin, target_user):
    user_id, email = target_user
    resp = await client.get(f"{BASE}/{user_id}", headers=_token(users_admin))
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == str(user_id)
    assert data["email"] == email
    assert data["is_active"] is True
    assert data["deleted_at"] is None


@pytest.mark.asyncio
async def test_get_user_not_found(client: AsyncClient, users_admin):
    resp = await client.get(f"{BASE}/{uuid.uuid4()}", headers=_token(users_admin))
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "USER_NOT_FOUND"


@pytest.mark.asyncio
async def test_get_user_readonly_can_access(client: AsyncClient, users_readonly, target_user):
    user_id, _ = target_user
    resp = await client.get(f"{BASE}/{user_id}", headers=_token(users_readonly))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_user_deactivate(client: AsyncClient, users_admin, target_user):
    user_id, _ = target_user
    resp = await client.patch(
        f"{BASE}/{user_id}",
        json={"is_active": False},
        headers=_token(users_admin),
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


@pytest.mark.asyncio
async def test_update_user_reactivate(client: AsyncClient, users_admin, target_user):
    user_id, _ = target_user
    resp = await client.patch(
        f"{BASE}/{user_id}",
        json={"is_active": True},
        headers=_token(users_admin),
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is True


@pytest.mark.asyncio
async def test_update_user_set_verified(client: AsyncClient, users_admin, target_user):
    user_id, _ = target_user
    resp = await client.patch(
        f"{BASE}/{user_id}",
        json={"is_verified": False},
        headers=_token(users_admin),
    )
    assert resp.status_code == 200
    assert resp.json()["is_verified"] is False

    # Restore
    await client.patch(
        f"{BASE}/{user_id}",
        json={"is_verified": True},
        headers=_token(users_admin),
    )


@pytest.mark.asyncio
async def test_update_user_not_found(client: AsyncClient, users_admin):
    resp = await client.patch(
        f"{BASE}/{uuid.uuid4()}",
        json={"is_active": False},
        headers=_token(users_admin),
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "USER_NOT_FOUND"


# ---------------------------------------------------------------------------
# Soft delete
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session")
async def deletable_user(db_engine) -> uuid.UUID:
    """A fresh user to be deleted in delete tests."""
    user_id = uuid.uuid4()
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            id=user_id,
            email=f"to-delete-{user_id}@test.local",
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.commit()
    return user_id


@pytest.mark.asyncio
async def test_delete_user(client: AsyncClient, users_admin, deletable_user):
    resp = await client.delete(f"{BASE}/{deletable_user}", headers=_token(users_admin))
    assert resp.status_code == 200
    assert "message" in resp.json()


@pytest.mark.asyncio
async def test_deleted_user_excluded_from_list(client: AsyncClient, users_admin, deletable_user):
    resp = await client.get(BASE, headers=_token(users_admin))
    ids = [u["id"] for u in resp.json()["items"]]
    assert str(deletable_user) not in ids


@pytest.mark.asyncio
async def test_deleted_user_visible_with_include_deleted(client: AsyncClient, users_admin, deletable_user):
    resp = await client.get(f"{BASE}?include_deleted=true&page_size=100", headers=_token(users_admin))
    ids = [u["id"] for u in resp.json()["items"]]
    assert str(deletable_user) in ids


@pytest.mark.asyncio
async def test_deleted_user_has_deleted_at_set(client: AsyncClient, users_admin, deletable_user):
    resp = await client.get(f"{BASE}?include_deleted=true&page_size=100", headers=_token(users_admin))
    deleted = next(u for u in resp.json()["items"] if u["id"] == str(deletable_user))
    assert deleted["deleted_at"] is not None


@pytest.mark.asyncio
async def test_update_deleted_user_returns_409(client: AsyncClient, users_admin, deletable_user):
    resp = await client.patch(
        f"{BASE}/{deletable_user}",
        json={"is_active": True},
        headers=_token(users_admin),
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "USER_DELETED"


@pytest.mark.asyncio
async def test_delete_not_found(client: AsyncClient, users_admin):
    resp = await client.delete(f"{BASE}/{uuid.uuid4()}", headers=_token(users_admin))
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "USER_NOT_FOUND"
