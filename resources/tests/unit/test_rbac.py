"""Unit tests: RBAC permission resolution via get_permissions controller."""

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from src.controllers.users import get_permissions
from src.models.rbac import Permission, Role, RolePermission, UserRole

pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_get_permissions_returns_roles_and_permissions(db_engine: AsyncEngine):
    user_id = uuid.uuid4()
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        admin_role = Role(name=f"admin_{user_id.hex[:8]}")
        viewer_role = Role(name=f"viewer_{user_id.hex[:8]}")
        session.add_all([admin_role, viewer_role])
        await session.flush()

        read_perm = Permission(name=f"users:read_{user_id.hex[:8]}")
        write_perm = Permission(name=f"users:write_{user_id.hex[:8]}")
        session.add_all([read_perm, write_perm])
        await session.flush()

        session.add_all(
            [
                RolePermission(role_id=admin_role.id, permission_id=read_perm.id),
                RolePermission(role_id=admin_role.id, permission_id=write_perm.id),
                RolePermission(role_id=viewer_role.id, permission_id=read_perm.id),
                UserRole(user_id=user_id, role_id=admin_role.id),
                UserRole(user_id=user_id, role_id=viewer_role.id),
            ]
        )
        await session.commit()

        result = await get_permissions(str(user_id), session)

    assert result.user_id == str(user_id)
    assert set(result.roles) == {admin_role.name, viewer_role.name}
    assert set(result.permissions) == {read_perm.name, write_perm.name}


async def test_get_permissions_no_roles_returns_empty(db_engine: AsyncEngine):
    user_id = uuid.uuid4()
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        result = await get_permissions(str(user_id), session)

    assert result.roles == []
    assert result.permissions == []


async def test_get_permissions_deduplicates_permissions(db_engine: AsyncEngine):
    """Two roles sharing the same permission must not produce duplicates."""
    user_id = uuid.uuid4()
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        role_a = Role(name=f"role_a_{user_id.hex[:8]}")
        role_b = Role(name=f"role_b_{user_id.hex[:8]}")
        perm = Permission(name=f"shared:perm_{user_id.hex[:8]}")
        session.add_all([role_a, role_b, perm])
        await session.flush()

        session.add_all(
            [
                RolePermission(role_id=role_a.id, permission_id=perm.id),
                RolePermission(role_id=role_b.id, permission_id=perm.id),
                UserRole(user_id=user_id, role_id=role_a.id),
                UserRole(user_id=user_id, role_id=role_b.id),
            ]
        )
        await session.commit()

        result = await get_permissions(str(user_id), session)

    assert result.permissions.count(perm.name) == 1
