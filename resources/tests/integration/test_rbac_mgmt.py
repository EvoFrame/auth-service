"""Integration tests: RBAC management endpoints (roles, permissions, assignments)."""

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
BASE = "/api/v1/rbac"

_ph = PasswordHasher()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _token(user_id: uuid.UUID) -> str:
    now = datetime.now(UTC)
    payload = {
        "jti": str(uuid.uuid4()),
        "sub": str(user_id),
        "email": "admin@example.com",
        "roles": [],
        "type": "user",
        "iss": settings.SERVICE_ID,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=900)).timestamp()),
    }
    return jwt.encode(payload, settings.RS256_PRIVATE_KEY, algorithm="RS256")


def _auth(user_id: uuid.UUID) -> dict[str, str]:
    return {"authorization": f"Bearer {_token(user_id)}"}


# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session")
async def admin_user(db_engine) -> uuid.UUID:
    """Create a user seeded with roles:read and roles:write permissions."""
    from sqlalchemy import select

    user_id = uuid.uuid4()

    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            id=user_id,
            email=f"rbac-admin-{user_id}@test.local",
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.flush()

        # Upsert permissions — they may already exist from another test run scope
        async def _get_or_create_perm(name: str) -> Permission:
            result = await session.execute(select(Permission).where(Permission.name == name))
            perm = result.scalar_one_or_none()
            if not perm:
                perm = Permission(name=name, description="seed")
                session.add(perm)
                await session.flush()
            return perm

        read_perm = await _get_or_create_perm("roles:read")
        write_perm = await _get_or_create_perm("roles:write")

        role = Role(name=f"rbac-admin-role-{user_id}")
        session.add(role)
        await session.flush()

        session.add(RolePermission(role_id=role.id, permission_id=read_perm.id))
        session.add(RolePermission(role_id=role.id, permission_id=write_perm.id))
        session.add(UserRole(user_id=user_id, role_id=role.id))
        await session.commit()

    return user_id


@pytest_asyncio.fixture(scope="session")
async def readonly_user(db_engine, admin_user) -> uuid.UUID:
    """Create a user with only roles:read (no write). Depends on admin_user to ensure permissions exist."""
    user_id = uuid.uuid4()

    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            id=user_id,
            email=f"rbac-readonly-{user_id}@test.local",
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
        )
        session.add(user)

        # Fetch existing roles:read permission (created by admin_user fixture)
        from sqlalchemy import select

        read_perm_result = await session.execute(select(Permission).where(Permission.name == "roles:read"))
        read_perm = read_perm_result.scalar_one()

        role = Role(name=f"rbac-readonly-role-{user_id}")
        session.add(role)
        await session.flush()

        session.add(RolePermission(role_id=role.id, permission_id=read_perm.id))
        session.add(UserRole(user_id=user_id, role_id=role.id))
        await session.commit()

    return user_id


@pytest_asyncio.fixture(scope="session")
async def unprivileged_user(db_engine) -> uuid.UUID:
    """Create a user with no RBAC permissions."""
    user_id = uuid.uuid4()

    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            id=user_id,
            email=f"rbac-none-{user_id}@test.local",
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.commit()

    return user_id


# ---------------------------------------------------------------------------
# Auth guard tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_roles_requires_auth(client: AsyncClient):
    resp = await client.get(f"{BASE}/roles")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_roles_requires_roles_read(client: AsyncClient, unprivileged_user):
    resp = await client.get(f"{BASE}/roles", headers=_auth(unprivileged_user))
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_create_role_requires_roles_write(client: AsyncClient, readonly_user):
    resp = await client.post(
        f"{BASE}/roles", json={"name": "should-fail"}, headers=_auth(readonly_user)
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Role CRUD
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_role(client: AsyncClient, admin_user):
    resp = await client.post(
        f"{BASE}/roles",
        json={"name": "test-role", "description": "A test role"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "test-role"
    assert data["description"] == "A test role"
    assert "id" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_create_role_duplicate_returns_409(client: AsyncClient, admin_user):
    resp = await client.post(
        f"{BASE}/roles",
        json={"name": "test-role"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "CONFLICT"


@pytest.mark.asyncio
async def test_list_roles(client: AsyncClient, admin_user):
    resp = await client.get(f"{BASE}/roles", headers=_auth(admin_user))
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1
    names = [r["name"] for r in data["items"]]
    assert "test-role" in names


@pytest.mark.asyncio
async def test_get_role(client: AsyncClient, admin_user):
    list_resp = await client.get(f"{BASE}/roles", headers=_auth(admin_user))
    role_id = next(r["id"] for r in list_resp.json()["items"] if r["name"] == "test-role")

    resp = await client.get(f"{BASE}/roles/{role_id}", headers=_auth(admin_user))
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == role_id
    assert data["name"] == "test-role"
    assert "permissions" in data
    assert isinstance(data["permissions"], list)


@pytest.mark.asyncio
async def test_get_role_not_found(client: AsyncClient, admin_user):
    resp = await client.get(f"{BASE}/roles/{uuid.uuid4()}", headers=_auth(admin_user))
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_update_role(client: AsyncClient, admin_user):
    list_resp = await client.get(f"{BASE}/roles", headers=_auth(admin_user))
    role_id = next(r["id"] for r in list_resp.json()["items"] if r["name"] == "test-role")

    resp = await client.patch(
        f"{BASE}/roles/{role_id}",
        json={"description": "Updated description"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 200
    assert resp.json()["description"] == "Updated description"


# ---------------------------------------------------------------------------
# Permission CRUD
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_permission(client: AsyncClient, admin_user):
    resp = await client.post(
        f"{BASE}/permissions",
        json={"name": "users:read", "description": "Can read users"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "users:read"
    assert "id" in data


@pytest.mark.asyncio
async def test_create_permission_duplicate_returns_409(client: AsyncClient, admin_user):
    resp = await client.post(
        f"{BASE}/permissions",
        json={"name": "users:read"},
        headers=_auth(admin_user),
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_list_permissions(client: AsyncClient, admin_user):
    resp = await client.get(f"{BASE}/permissions", headers=_auth(admin_user))
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert data["total"] >= 1
    names = [p["name"] for p in data["items"]]
    assert "users:read" in names


# ---------------------------------------------------------------------------
# Role ↔ Permission assignment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assign_permission_to_role(client: AsyncClient, admin_user):
    list_roles_resp = await client.get(f"{BASE}/roles", headers=_auth(admin_user))
    role_id = next(r["id"] for r in list_roles_resp.json()["items"] if r["name"] == "test-role")

    list_perms_resp = await client.get(f"{BASE}/permissions", headers=_auth(admin_user))
    perm_id = next(p["id"] for p in list_perms_resp.json()["items"] if p["name"] == "users:read")

    resp = await client.post(
        f"{BASE}/roles/{role_id}/permissions/{perm_id}",
        headers=_auth(admin_user),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == role_id
    perm_names = [p["name"] for p in data["permissions"]]
    assert "users:read" in perm_names


@pytest.mark.asyncio
async def test_assign_permission_to_role_idempotent(client: AsyncClient, admin_user):
    """Assigning the same permission twice should return 200 without error."""
    list_roles_resp = await client.get(f"{BASE}/roles", headers=_auth(admin_user))
    role_id = next(r["id"] for r in list_roles_resp.json()["items"] if r["name"] == "test-role")

    list_perms_resp = await client.get(f"{BASE}/permissions", headers=_auth(admin_user))
    perm_id = next(p["id"] for p in list_perms_resp.json()["items"] if p["name"] == "users:read")

    resp = await client.post(
        f"{BASE}/roles/{role_id}/permissions/{perm_id}",
        headers=_auth(admin_user),
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_remove_permission_from_role(client: AsyncClient, admin_user):
    list_roles_resp = await client.get(f"{BASE}/roles", headers=_auth(admin_user))
    role_id = next(r["id"] for r in list_roles_resp.json()["items"] if r["name"] == "test-role")

    list_perms_resp = await client.get(f"{BASE}/permissions", headers=_auth(admin_user))
    perm_id = next(p["id"] for p in list_perms_resp.json()["items"] if p["name"] == "users:read")

    resp = await client.delete(
        f"{BASE}/roles/{role_id}/permissions/{perm_id}",
        headers=_auth(admin_user),
    )
    assert resp.status_code == 204

    # Verify removed
    role_resp = await client.get(f"{BASE}/roles/{role_id}", headers=_auth(admin_user))
    perm_names = [p["name"] for p in role_resp.json()["permissions"]]
    assert "users:read" not in perm_names


@pytest.mark.asyncio
async def test_remove_permission_not_found(client: AsyncClient, admin_user):
    list_roles_resp = await client.get(f"{BASE}/roles", headers=_auth(admin_user))
    role_id = next(r["id"] for r in list_roles_resp.json()["items"] if r["name"] == "test-role")

    resp = await client.delete(
        f"{BASE}/roles/{role_id}/permissions/{uuid.uuid4()}",
        headers=_auth(admin_user),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# User ↔ Role assignment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_user_roles_empty(client: AsyncClient, admin_user, unprivileged_user):
    resp = await client.get(f"{BASE}/users/{unprivileged_user}/roles", headers=_auth(admin_user))
    assert resp.status_code == 200
    data = resp.json()
    assert data["user_id"] == str(unprivileged_user)
    assert data["roles"] == []
    assert data["permissions"] == []


@pytest.mark.asyncio
async def test_assign_role_to_user(client: AsyncClient, admin_user, unprivileged_user):
    list_roles_resp = await client.get(f"{BASE}/roles", headers=_auth(admin_user))
    role_id = next(r["id"] for r in list_roles_resp.json()["items"] if r["name"] == "test-role")

    resp = await client.post(
        f"{BASE}/users/{unprivileged_user}/roles/{role_id}",
        headers=_auth(admin_user),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["user_id"] == str(unprivileged_user)
    role_names = [r["name"] for r in data["roles"]]
    assert "test-role" in role_names


@pytest.mark.asyncio
async def test_assign_role_to_user_idempotent(client: AsyncClient, admin_user, unprivileged_user):
    list_roles_resp = await client.get(f"{BASE}/roles", headers=_auth(admin_user))
    role_id = next(r["id"] for r in list_roles_resp.json()["items"] if r["name"] == "test-role")

    resp = await client.post(
        f"{BASE}/users/{unprivileged_user}/roles/{role_id}",
        headers=_auth(admin_user),
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_remove_role_from_user(client: AsyncClient, admin_user, unprivileged_user):
    list_roles_resp = await client.get(f"{BASE}/roles", headers=_auth(admin_user))
    role_id = next(r["id"] for r in list_roles_resp.json()["items"] if r["name"] == "test-role")

    resp = await client.delete(
        f"{BASE}/users/{unprivileged_user}/roles/{role_id}",
        headers=_auth(admin_user),
    )
    assert resp.status_code == 204

    # Verify removed
    roles_resp = await client.get(
        f"{BASE}/users/{unprivileged_user}/roles", headers=_auth(admin_user)
    )
    role_names = [r["name"] for r in roles_resp.json()["roles"]]
    assert "test-role" not in role_names


@pytest.mark.asyncio
async def test_remove_role_from_user_not_found(client: AsyncClient, admin_user, unprivileged_user):
    resp = await client.delete(
        f"{BASE}/users/{unprivileged_user}/roles/{uuid.uuid4()}",
        headers=_auth(admin_user),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_assign_role_to_nonexistent_user(client: AsyncClient, admin_user):
    list_roles_resp = await client.get(f"{BASE}/roles", headers=_auth(admin_user))
    role_id = next(r["id"] for r in list_roles_resp.json()["items"] if r["name"] == "test-role")

    resp = await client.post(
        f"{BASE}/users/{uuid.uuid4()}/roles/{role_id}",
        headers=_auth(admin_user),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Delete permission cascades
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_permission_removes_from_roles(client: AsyncClient, admin_user):
    """Deleting a permission cascades removal from role_permissions."""
    create_perm_resp = await client.post(
        f"{BASE}/permissions",
        json={"name": "cascade-test-perm"},
        headers=_auth(admin_user),
    )
    perm_id = create_perm_resp.json()["id"]

    list_roles_resp = await client.get(f"{BASE}/roles", headers=_auth(admin_user))
    role_id = next(r["id"] for r in list_roles_resp.json()["items"] if r["name"] == "test-role")

    await client.post(f"{BASE}/roles/{role_id}/permissions/{perm_id}", headers=_auth(admin_user))

    del_resp = await client.delete(f"{BASE}/permissions/{perm_id}", headers=_auth(admin_user))
    assert del_resp.status_code == 204

    role_resp = await client.get(f"{BASE}/roles/{role_id}", headers=_auth(admin_user))
    perm_names = [p["name"] for p in role_resp.json()["permissions"]]
    assert "cascade-test-perm" not in perm_names


# ---------------------------------------------------------------------------
# Delete role cascades
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_role(client: AsyncClient, admin_user):
    create_resp = await client.post(
        f"{BASE}/roles",
        json={"name": "role-to-delete"},
        headers=_auth(admin_user),
    )
    role_id = create_resp.json()["id"]

    del_resp = await client.delete(f"{BASE}/roles/{role_id}", headers=_auth(admin_user))
    assert del_resp.status_code == 204

    get_resp = await client.get(f"{BASE}/roles/{role_id}", headers=_auth(admin_user))
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_role_not_found(client: AsyncClient, admin_user):
    resp = await client.delete(f"{BASE}/roles/{uuid.uuid4()}", headers=_auth(admin_user))
    assert resp.status_code == 404
