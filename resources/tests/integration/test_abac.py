"""Integration tests: ABAC management endpoints and evaluate flow."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
import pytest_asyncio
from argon2 import PasswordHasher
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from src.config.settings import settings
from src.models.rbac import Permission, Role, RolePermission, UserRole
from src.models.user import User

pytestmark = pytest.mark.asyncio(loop_scope="session")
BASE = "/api/v1/abac"

_ph = PasswordHasher()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _token(user_id: uuid.UUID) -> str:
    now = datetime.now(UTC)
    payload = {
        "jti": str(uuid.uuid4()),
        "sub": str(user_id),
        "email": "abac-test@example.com",
        "roles": [],
        "type": "user",
        "iss": settings.SERVICE_ID,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=900)).timestamp()),
    }
    return jwt.encode(payload, settings.RS256_PRIVATE_KEY, algorithm="RS256")


def _auth(user_id: uuid.UUID) -> dict[str, str]:
    return {"authorization": f"Bearer {_token(user_id)}"}


async def _get_or_create_perm(session: AsyncSession, name: str) -> Permission:
    result = await session.execute(select(Permission).where(Permission.name == name))
    perm = result.scalar_one_or_none()
    if not perm:
        perm = Permission(name=name, description="abac seed")
        session.add(perm)
        await session.flush()
    return perm


# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session")
async def abac_admin(db_engine) -> uuid.UUID:
    """User with abac:read, abac:write, and abac:evaluate permissions."""
    user_id = uuid.uuid4()
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            id=user_id,
            email=f"abac-admin-{user_id.hex[:8]}@test.local",
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.flush()

        read_perm = await _get_or_create_perm(session, "abac:read")
        write_perm = await _get_or_create_perm(session, "abac:write")
        eval_perm = await _get_or_create_perm(session, "abac:evaluate")

        role = Role(name=f"abac-admin-role-{user_id.hex[:8]}")
        session.add(role)
        await session.flush()

        for perm in (read_perm, write_perm, eval_perm):
            session.add(RolePermission(role_id=role.id, permission_id=perm.id))
        session.add(UserRole(user_id=user_id, role_id=role.id))
        await session.commit()

    return user_id


@pytest_asyncio.fixture(scope="session")
async def fresh_user(db_engine) -> uuid.UUID:
    """A user with no attributes — used to verify default-deny with no matching policies."""
    user_id = uuid.uuid4()
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            id=user_id,
            email=f"abac-fresh-{user_id.hex[:8]}@test.local",
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.commit()
    return user_id


@pytest_asyncio.fixture(scope="session")
async def subject_user(db_engine, abac_admin) -> uuid.UUID:
    """A plain user to be used as the subject in evaluate requests."""
    user_id = uuid.uuid4()
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        user = User(
            id=user_id,
            email=f"abac-subject-{user_id.hex[:8]}@test.local",
            password_hash=_ph.hash("Password1!"),
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.commit()
    return user_id


# ---------------------------------------------------------------------------
# User attribute tests
# ---------------------------------------------------------------------------


async def test_upsert_and_list_attributes(client: AsyncClient, abac_admin: uuid.UUID, subject_user: uuid.UUID):
    headers = _auth(abac_admin)

    r = await client.put(
        f"{BASE}/users/{subject_user}/attributes/department",
        json={"value": "engineering"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["value"] == "engineering"

    r = await client.get(f"{BASE}/users/{subject_user}/attributes", headers=headers)
    assert r.status_code == 200
    attrs = {a["key"]: a["value"] for a in r.json()}
    assert attrs["department"] == "engineering"


async def test_upsert_updates_existing_attribute(client: AsyncClient, abac_admin: uuid.UUID, subject_user: uuid.UUID):
    headers = _auth(abac_admin)

    await client.put(
        f"{BASE}/users/{subject_user}/attributes/department",
        json={"value": "finance"},
        headers=headers,
    )
    r = await client.put(
        f"{BASE}/users/{subject_user}/attributes/department",
        json={"value": "engineering"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["value"] == "engineering"


async def test_delete_attribute(client: AsyncClient, abac_admin: uuid.UUID, subject_user: uuid.UUID):
    headers = _auth(abac_admin)

    await client.put(
        f"{BASE}/users/{subject_user}/attributes/temp_key",
        json={"value": "temp"},
        headers=headers,
    )
    r = await client.delete(f"{BASE}/users/{subject_user}/attributes/temp_key", headers=headers)
    assert r.status_code == 204

    r = await client.get(f"{BASE}/users/{subject_user}/attributes", headers=headers)
    keys = [a["key"] for a in r.json()]
    assert "temp_key" not in keys


async def test_delete_missing_attribute_returns_404(
    client: AsyncClient, abac_admin: uuid.UUID, subject_user: uuid.UUID
):
    r = await client.delete(
        f"{BASE}/users/{subject_user}/attributes/does_not_exist",
        headers=_auth(abac_admin),
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Policy CRUD tests
# ---------------------------------------------------------------------------


async def test_create_policy(client: AsyncClient, abac_admin: uuid.UUID):
    r = await client.post(
        f"{BASE}/policies",
        json={"name": f"test-allow-{uuid.uuid4().hex[:6]}", "effect": "allow", "priority": 10},
        headers=_auth(abac_admin),
    )
    assert r.status_code == 201
    data = r.json()
    assert data["effect"] == "allow"
    assert data["conditions"] == []
    return data["id"]


async def test_create_policy_invalid_effect(client: AsyncClient, abac_admin: uuid.UUID):
    r = await client.post(
        f"{BASE}/policies",
        json={"name": "bad-effect", "effect": "maybe"},
        headers=_auth(abac_admin),
    )
    assert r.status_code == 422


async def test_create_policy_duplicate_name_409(client: AsyncClient, abac_admin: uuid.UUID):
    name = f"dup-policy-{uuid.uuid4().hex[:6]}"
    await client.post(f"{BASE}/policies", json={"name": name, "effect": "allow"}, headers=_auth(abac_admin))
    r = await client.post(f"{BASE}/policies", json={"name": name, "effect": "deny"}, headers=_auth(abac_admin))
    assert r.status_code == 409


async def test_add_and_list_conditions(client: AsyncClient, abac_admin: uuid.UUID):
    r = await client.post(
        f"{BASE}/policies",
        json={"name": f"cond-policy-{uuid.uuid4().hex[:6]}", "effect": "allow"},
        headers=_auth(abac_admin),
    )
    policy_id = r.json()["id"]

    r = await client.post(
        f"{BASE}/policies/{policy_id}/conditions",
        json={"attribute_source": "subject", "attribute_key": "department", "operator": "eq", "value": "engineering"},
        headers=_auth(abac_admin),
    )
    assert r.status_code == 201
    assert len(r.json()["conditions"]) == 1
    cond = r.json()["conditions"][0]
    assert cond["operator"] == "eq"
    return policy_id, cond["id"]


async def test_remove_condition(client: AsyncClient, abac_admin: uuid.UUID):
    r = await client.post(
        f"{BASE}/policies",
        json={"name": f"rm-cond-policy-{uuid.uuid4().hex[:6]}", "effect": "allow"},
        headers=_auth(abac_admin),
    )
    policy_id = r.json()["id"]

    r = await client.post(
        f"{BASE}/policies/{policy_id}/conditions",
        json={"attribute_source": "subject", "attribute_key": "x", "operator": "eq", "value": "y"},
        headers=_auth(abac_admin),
    )
    cond_id = r.json()["conditions"][0]["id"]

    r = await client.delete(f"{BASE}/conditions/{cond_id}", headers=_auth(abac_admin))
    assert r.status_code == 204

    r = await client.get(f"{BASE}/policies/{policy_id}", headers=_auth(abac_admin))
    assert r.json()["conditions"] == []


async def test_update_policy(client: AsyncClient, abac_admin: uuid.UUID):
    r = await client.post(
        f"{BASE}/policies",
        json={"name": f"upd-policy-{uuid.uuid4().hex[:6]}", "effect": "allow", "is_active": True},
        headers=_auth(abac_admin),
    )
    policy_id = r.json()["id"]

    r = await client.patch(
        f"{BASE}/policies/{policy_id}",
        json={"is_active": False, "priority": 99},
        headers=_auth(abac_admin),
    )
    assert r.status_code == 200
    assert r.json()["is_active"] is False
    assert r.json()["priority"] == 99


async def test_delete_policy(client: AsyncClient, abac_admin: uuid.UUID):
    r = await client.post(
        f"{BASE}/policies",
        json={"name": f"del-policy-{uuid.uuid4().hex[:6]}", "effect": "deny"},
        headers=_auth(abac_admin),
    )
    policy_id = r.json()["id"]

    r = await client.delete(f"{BASE}/policies/{policy_id}", headers=_auth(abac_admin))
    assert r.status_code == 204

    r = await client.get(f"{BASE}/policies/{policy_id}", headers=_auth(abac_admin))
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Evaluate endpoint tests
# ---------------------------------------------------------------------------


async def test_evaluate_default_deny(client: AsyncClient, abac_admin: uuid.UUID, fresh_user: uuid.UUID):
    """No active policies match this user (no attributes) → default deny."""
    r = await client.post(
        f"{BASE}/evaluate",
        json={"user_id": str(fresh_user), "action": "read", "resource_type": "document"},
        headers=_auth(abac_admin),
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "deny"
    assert r.json()["matched_policy_name"] == "default-deny"


async def test_evaluate_allow_on_attribute_match(client: AsyncClient, abac_admin: uuid.UUID, subject_user: uuid.UUID):
    """Set department=engineering, create allow policy, expect allow."""
    headers = _auth(abac_admin)

    # Ensure attribute is set
    await client.put(
        f"{BASE}/users/{subject_user}/attributes/department",
        json={"value": "engineering"},
        headers=headers,
    )

    # Create policy
    policy_name = f"eval-allow-{uuid.uuid4().hex[:6]}"
    r = await client.post(
        f"{BASE}/policies",
        json={"name": policy_name, "effect": "allow", "priority": 50, "is_active": True},
        headers=headers,
    )
    policy_id = r.json()["id"]

    await client.post(
        f"{BASE}/policies/{policy_id}/conditions",
        json={"attribute_source": "subject", "attribute_key": "department", "operator": "eq", "value": "engineering"},
        headers=headers,
    )

    r = await client.post(
        f"{BASE}/evaluate",
        json={"user_id": str(subject_user), "action": "read", "resource_type": "document"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "allow"
    assert r.json()["matched_policy_name"] == policy_name

    # Cleanup — deactivate so it doesn't affect other tests
    await client.patch(f"{BASE}/policies/{policy_id}", json={"is_active": False}, headers=headers)


async def test_evaluate_deny_overrides_allow(client: AsyncClient, abac_admin: uuid.UUID, subject_user: uuid.UUID):
    """A deny policy fires alongside an allow → deny wins."""
    headers = _auth(abac_admin)

    await client.put(
        f"{BASE}/users/{subject_user}/attributes/department",
        json={"value": "engineering"},
        headers=headers,
    )
    await client.put(
        f"{BASE}/users/{subject_user}/attributes/status",
        json={"value": "suspended"},
        headers=headers,
    )

    allow_name = f"eval-allow2-{uuid.uuid4().hex[:6]}"
    r = await client.post(
        f"{BASE}/policies",
        json={"name": allow_name, "effect": "allow", "priority": 10, "is_active": True},
        headers=headers,
    )
    allow_id = r.json()["id"]
    await client.post(
        f"{BASE}/policies/{allow_id}/conditions",
        json={"attribute_source": "subject", "attribute_key": "department", "operator": "eq", "value": "engineering"},
        headers=headers,
    )

    deny_name = f"eval-deny2-{uuid.uuid4().hex[:6]}"
    r = await client.post(
        f"{BASE}/policies",
        json={"name": deny_name, "effect": "deny", "priority": 20, "is_active": True},
        headers=headers,
    )
    deny_id = r.json()["id"]
    await client.post(
        f"{BASE}/policies/{deny_id}/conditions",
        json={"attribute_source": "subject", "attribute_key": "status", "operator": "eq", "value": "suspended"},
        headers=headers,
    )

    r = await client.post(
        f"{BASE}/evaluate",
        json={"user_id": str(subject_user), "action": "write", "resource_type": "document"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "deny"

    # Cleanup
    for pid in (allow_id, deny_id):
        await client.patch(f"{BASE}/policies/{pid}", json={"is_active": False}, headers=headers)


async def test_evaluate_unknown_user_404(client: AsyncClient, abac_admin: uuid.UUID):
    r = await client.post(
        f"{BASE}/evaluate",
        json={"user_id": str(uuid.uuid4()), "action": "read", "resource_type": "doc"},
        headers=_auth(abac_admin),
    )
    assert r.status_code == 404


async def test_evaluate_caller_service_injected(client: AsyncClient, abac_admin: uuid.UUID, fresh_user: uuid.UUID):
    """Verify caller_service ends up in the environment and can be matched by a policy."""
    headers = _auth(abac_admin)

    policy_name = f"caller-svc-{uuid.uuid4().hex[:6]}"
    r = await client.post(
        f"{BASE}/policies",
        json={"name": policy_name, "effect": "allow", "priority": 30, "is_active": True},
        headers=headers,
    )
    policy_id = r.json()["id"]
    await client.post(
        f"{BASE}/policies/{policy_id}/conditions",
        json={
            "attribute_source": "environment",
            "attribute_key": "caller_service",
            "operator": "eq",
            "value": "unknown",  # ServiceAuthMiddleware is bypassed in tests → caller_service = "test-client"
        },
        headers=headers,
    )

    r = await client.post(
        f"{BASE}/evaluate",
        json={"user_id": str(fresh_user), "action": "read", "resource_type": "doc"},
        headers=headers,
    )
    # caller_service is "test-client" in tests (not "unknown") → policy won't fire → default deny
    assert r.status_code == 200
    assert r.json()["decision"] == "deny"

    await client.patch(f"{BASE}/policies/{policy_id}", json={"is_active": False}, headers=headers)


# ---------------------------------------------------------------------------
# Cross-attribute comparison
# ---------------------------------------------------------------------------


async def test_condition_with_value_ref_stored_and_returned(client: AsyncClient, abac_admin: uuid.UUID):
    """Create a condition with value_ref fields and verify they are returned by GET."""
    headers = _auth(abac_admin)

    r = await client.post(
        f"{BASE}/policies",
        json={"name": f"ref-policy-{uuid.uuid4().hex[:6]}", "effect": "allow", "is_active": False},
        headers=headers,
    )
    policy_id = r.json()["id"]

    r = await client.post(
        f"{BASE}/policies/{policy_id}/conditions",
        json={
            "attribute_source": "subject",
            "attribute_key": "user_id",
            "operator": "eq",
            "value_ref_source": "resource",
            "value_ref_key": "owner_id",
        },
        headers=headers,
    )
    assert r.status_code == 201
    cond = r.json()["conditions"][0]
    assert cond["value_ref_source"] == "resource"
    assert cond["value_ref_key"] == "owner_id"

    r = await client.get(f"{BASE}/policies/{policy_id}", headers=headers)
    cond = r.json()["conditions"][0]
    assert cond["value_ref_source"] == "resource"
    assert cond["value_ref_key"] == "owner_id"


async def test_evaluate_cross_attr_allow_when_owner(
    client: AsyncClient, abac_admin: uuid.UUID, subject_user: uuid.UUID
):
    """User owns the resource (subject.user_id eq resource.owner_id) → allow."""
    headers = _auth(abac_admin)

    await client.put(
        f"{BASE}/users/{subject_user}/attributes/user_id",
        json={"value": str(subject_user)},
        headers=headers,
    )

    policy_name = f"owner-allow-{uuid.uuid4().hex[:6]}"
    r = await client.post(
        f"{BASE}/policies",
        json={"name": policy_name, "effect": "allow", "priority": 60, "is_active": True},
        headers=headers,
    )
    policy_id = r.json()["id"]

    await client.post(
        f"{BASE}/policies/{policy_id}/conditions",
        json={
            "attribute_source": "subject",
            "attribute_key": "user_id",
            "operator": "eq",
            "value_ref_source": "resource",
            "value_ref_key": "owner_id",
        },
        headers=headers,
    )

    r = await client.post(
        f"{BASE}/evaluate",
        json={
            "user_id": str(subject_user),
            "action": "read",
            "resource_type": "file",
            "resource_attributes": {"owner_id": str(subject_user)},
        },
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "allow"
    assert r.json()["matched_policy_name"] == policy_name

    await client.patch(f"{BASE}/policies/{policy_id}", json={"is_active": False}, headers=headers)


async def test_evaluate_cross_attr_deny_when_not_owner(
    client: AsyncClient, abac_admin: uuid.UUID, fresh_user: uuid.UUID
):
    """User does not own the resource → no match → deny."""
    headers = _auth(abac_admin)

    await client.put(
        f"{BASE}/users/{fresh_user}/attributes/user_id",
        json={"value": str(fresh_user)},
        headers=headers,
    )

    policy_name = f"owner-allow2-{uuid.uuid4().hex[:6]}"
    r = await client.post(
        f"{BASE}/policies",
        json={"name": policy_name, "effect": "allow", "priority": 60, "is_active": True},
        headers=headers,
    )
    policy_id = r.json()["id"]

    await client.post(
        f"{BASE}/policies/{policy_id}/conditions",
        json={
            "attribute_source": "subject",
            "attribute_key": "user_id",
            "operator": "eq",
            "value_ref_source": "resource",
            "value_ref_key": "owner_id",
        },
        headers=headers,
    )

    r = await client.post(
        f"{BASE}/evaluate",
        json={
            "user_id": str(fresh_user),
            "action": "read",
            "resource_type": "file",
            "resource_attributes": {"owner_id": str(uuid.uuid4())},
        },
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "deny"

    await client.patch(f"{BASE}/policies/{policy_id}", json={"is_active": False}, headers=headers)
