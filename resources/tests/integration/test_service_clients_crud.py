"""Integration tests: service client CRUD endpoints."""

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
BASE = "/api/v1/service-clients"

_ph = PasswordHasher()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _token(user_id: uuid.UUID) -> dict[str, str]:
    now = datetime.now(UTC)
    payload = {
        "jti": str(uuid.uuid4()),
        "sub": str(user_id),
        "email": "sc-admin@test.local",
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
async def sc_admin(db_engine) -> uuid.UUID:
    """User with service_clients:read and service_clients:write permissions."""
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
            email=f"sc-admin-{user_id}@test.local",
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.flush()

        read_perm = await _get_or_create_perm(session, "service_clients:read")
        write_perm = await _get_or_create_perm(session, "service_clients:write")

        role = Role(name=f"sc-admin-role-{user_id}")
        session.add(role)
        await session.flush()

        session.add(RolePermission(role_id=role.id, permission_id=read_perm.id))
        session.add(RolePermission(role_id=role.id, permission_id=write_perm.id))
        session.add(UserRole(user_id=user_id, role_id=role.id))
        await session.commit()

    return user_id


@pytest_asyncio.fixture(scope="session")
async def sc_readonly(db_engine, sc_admin) -> uuid.UUID:
    """User with service_clients:read only."""
    from sqlalchemy import select

    user_id = uuid.uuid4()

    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            id=user_id,
            email=f"sc-readonly-{user_id}@test.local",
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.flush()

        read_perm_result = await session.execute(
            select(Permission).where(Permission.name == "service_clients:read")
        )
        read_perm = read_perm_result.scalar_one()

        role = Role(name=f"sc-readonly-role-{user_id}")
        session.add(role)
        await session.flush()

        session.add(RolePermission(role_id=role.id, permission_id=read_perm.id))
        session.add(UserRole(user_id=user_id, role_id=role.id))
        await session.commit()

    return user_id


# ---------------------------------------------------------------------------
# Auth guard tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_service_client_requires_auth(client: AsyncClient):
    resp = await client.post(BASE, json={"service_id": "test"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_create_service_client_requires_write_permission(client: AsyncClient, sc_readonly):
    resp = await client.post(
        BASE, json={"service_id": "should-fail"}, headers=_token(sc_readonly)
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_service_clients_requires_auth(client: AsyncClient):
    resp = await client.get(BASE)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_service_client(client: AsyncClient, sc_admin):
    resp = await client.post(
        BASE,
        json={"service_id": "my-service"},
        headers=_token(sc_admin),
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["service_id"] == "my-service"
    assert "service_secret" in data
    assert len(data["service_secret"]) > 20
    assert data["is_active"] is True
    assert "id" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_create_service_client_duplicate_returns_409(client: AsyncClient, sc_admin):
    resp = await client.post(
        BASE,
        json={"service_id": "my-service"},
        headers=_token(sc_admin),
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "SERVICE_ID_TAKEN"


@pytest.mark.asyncio
async def test_created_secret_can_issue_token(client: AsyncClient, sc_admin):
    """The one-time secret returned at creation should work for token issuance."""
    create_resp = await client.post(
        BASE,
        json={"service_id": "tokenable-service"},
        headers=_token(sc_admin),
    )
    secret = create_resp.json()["service_secret"]

    token_resp = await client.post(
        f"{BASE}/token",
        json={"service_id": "tokenable-service", "service_secret": secret},
    )
    assert token_resp.status_code == 200
    assert token_resp.json()["access_token"]


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_service_clients(client: AsyncClient, sc_admin):
    resp = await client.get(BASE, headers=_token(sc_admin))
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1
    service_ids = [c["service_id"] for c in data["items"]]
    assert "my-service" in service_ids


@pytest.mark.asyncio
async def test_list_service_clients_pagination(client: AsyncClient, sc_admin):
    resp = await client.get(f"{BASE}?page=1&page_size=1", headers=_token(sc_admin))
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 1
    assert data["pages"] >= 1


@pytest.mark.asyncio
async def test_list_service_clients_readonly_can_access(client: AsyncClient, sc_readonly):
    resp = await client.get(BASE, headers=_token(sc_readonly))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Get
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_service_client(client: AsyncClient, sc_admin):
    resp = await client.get(f"{BASE}/my-service", headers=_token(sc_admin))
    assert resp.status_code == 200
    data = resp.json()
    assert data["service_id"] == "my-service"
    assert data["is_active"] is True
    assert "deleted_at" in data


@pytest.mark.asyncio
async def test_get_service_client_not_found(client: AsyncClient, sc_admin):
    resp = await client.get(f"{BASE}/ghost-service-xyz", headers=_token(sc_admin))
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "SERVICE_CLIENT_NOT_FOUND"


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_service_client_deactivate(client: AsyncClient, sc_admin):
    resp = await client.patch(
        f"{BASE}/my-service",
        json={"is_active": False},
        headers=_token(sc_admin),
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


@pytest.mark.asyncio
async def test_update_service_client_reactivate(client: AsyncClient, sc_admin):
    resp = await client.patch(
        f"{BASE}/my-service",
        json={"is_active": True},
        headers=_token(sc_admin),
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is True


@pytest.mark.asyncio
async def test_update_service_client_not_found(client: AsyncClient, sc_admin):
    resp = await client.patch(
        f"{BASE}/ghost-service-xyz",
        json={"is_active": False},
        headers=_token(sc_admin),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_requires_write_permission(client: AsyncClient, sc_readonly):
    resp = await client.patch(
        f"{BASE}/my-service",
        json={"is_active": False},
        headers=_token(sc_readonly),
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Deactivated client cannot issue tokens
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deactivated_service_cannot_issue_token(client: AsyncClient, sc_admin):
    create_resp = await client.post(
        BASE,
        json={"service_id": "disabled-service"},
        headers=_token(sc_admin),
    )
    secret = create_resp.json()["service_secret"]

    await client.patch(
        f"{BASE}/disabled-service",
        json={"is_active": False},
        headers=_token(sc_admin),
    )

    token_resp = await client.post(
        f"{BASE}/token",
        json={"service_id": "disabled-service", "service_secret": secret},
    )
    assert token_resp.status_code == 401


# ---------------------------------------------------------------------------
# Soft delete
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_service_client(client: AsyncClient, sc_admin):
    await client.post(BASE, json={"service_id": "to-delete"}, headers=_token(sc_admin))

    resp = await client.delete(f"{BASE}/to-delete", headers=_token(sc_admin))
    assert resp.status_code == 200
    assert "message" in resp.json()


@pytest.mark.asyncio
async def test_deleted_service_client_excluded_from_list(client: AsyncClient, sc_admin):
    resp = await client.get(BASE, headers=_token(sc_admin))
    service_ids = [c["service_id"] for c in resp.json()["items"]]
    assert "to-delete" not in service_ids


@pytest.mark.asyncio
async def test_deleted_service_client_visible_with_include_deleted(client: AsyncClient, sc_admin):
    resp = await client.get(f"{BASE}?include_deleted=true", headers=_token(sc_admin))
    service_ids = [c["service_id"] for c in resp.json()["items"]]
    assert "to-delete" in service_ids


@pytest.mark.asyncio
async def test_delete_already_deleted_returns_409(client: AsyncClient, sc_admin):
    resp = await client.delete(f"{BASE}/to-delete", headers=_token(sc_admin))
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "SERVICE_CLIENT_ALREADY_DELETED"


@pytest.mark.asyncio
async def test_deleted_service_cannot_issue_token(client: AsyncClient, sc_admin):
    """Soft-deleted service client must be rejected at token issuance."""
    create_resp = await client.post(
        BASE,
        json={"service_id": "soon-deleted"},
        headers=_token(sc_admin),
    )
    secret = create_resp.json()["service_secret"]

    await client.delete(f"{BASE}/soon-deleted", headers=_token(sc_admin))

    token_resp = await client.post(
        f"{BASE}/token",
        json={"service_id": "soon-deleted", "service_secret": secret},
    )
    assert token_resp.status_code == 401


@pytest.mark.asyncio
async def test_update_deleted_service_client_returns_409(client: AsyncClient, sc_admin):
    resp = await client.patch(
        f"{BASE}/to-delete",
        json={"is_active": True},
        headers=_token(sc_admin),
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "SERVICE_CLIENT_DELETED"


@pytest.mark.asyncio
async def test_delete_requires_write_permission(client: AsyncClient, sc_readonly):
    resp = await client.delete(f"{BASE}/my-service", headers=_token(sc_readonly))
    assert resp.status_code == 403
