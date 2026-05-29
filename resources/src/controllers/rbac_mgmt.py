"""RBAC management controller — roles, permissions, and assignments."""

import uuid

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.libs.errors import AppError
from src.libs.pagination import PagedResponse, paginate
from src.models.rbac import Permission, Role, RolePermission, UserRole
from src.models.user import User
from src.schemas.rbac_mgmt import (
    PermissionCreateRequest,
    PermissionResponse,
    RoleCreateRequest,
    RoleDetailResponse,
    RoleResponse,
    RoleUpdateRequest,
    UserRolesResponse,
)

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


async def list_roles(
    session: AsyncSession, page: int = 1, page_size: int = 50
) -> PagedResponse[RoleResponse]:
    total = (await session.execute(select(func.count()).select_from(Role))).scalar_one()
    roles = (
        await session.execute(
            select(Role).order_by(Role.name).offset((page - 1) * page_size).limit(page_size)
        )
    ).scalars().all()
    return paginate(
        [RoleResponse.model_validate(r, from_attributes=True) for r in roles], total, page, page_size
    )


async def create_role(data: RoleCreateRequest, session: AsyncSession) -> RoleResponse:
    existing = await session.execute(select(Role).where(Role.name == data.name))
    if existing.scalar_one_or_none():
        raise AppError("CONFLICT", f"Role '{data.name}' already exists.", status_code=409)

    role = Role(name=data.name, description=data.description)
    session.add(role)
    await session.commit()
    await session.refresh(role)
    logger.info("rbac.role_created", role_id=str(role.id), name=role.name)
    return RoleResponse.model_validate(role, from_attributes=True)


async def get_role(role_id: uuid.UUID, session: AsyncSession) -> RoleDetailResponse:
    role = await session.get(Role, role_id)
    if not role:
        raise AppError("NOT_FOUND", "Role not found.", status_code=404)

    result = await session.execute(
        select(Permission)
        .join(RolePermission, Permission.id == RolePermission.permission_id)
        .where(RolePermission.role_id == role_id)
        .order_by(Permission.name)
    )
    permissions = [
        PermissionResponse.model_validate(p, from_attributes=True) for p in result.scalars().all()
    ]
    return RoleDetailResponse(
        id=role.id,
        name=role.name,
        description=role.description,
        created_at=role.created_at,
        permissions=permissions,
    )


async def update_role(
    role_id: uuid.UUID, data: RoleUpdateRequest, session: AsyncSession
) -> RoleResponse:
    role = await session.get(Role, role_id)
    if not role:
        raise AppError("NOT_FOUND", "Role not found.", status_code=404)

    if data.name is not None and data.name != role.name:
        conflict = await session.execute(select(Role).where(Role.name == data.name))
        if conflict.scalar_one_or_none():
            raise AppError("CONFLICT", f"Role '{data.name}' already exists.", status_code=409)
        role.name = data.name
    if data.description is not None:
        role.description = data.description

    session.add(role)
    await session.commit()
    await session.refresh(role)
    logger.info("rbac.role_updated", role_id=str(role_id))
    return RoleResponse.model_validate(role, from_attributes=True)


async def delete_role(role_id: uuid.UUID, session: AsyncSession) -> None:
    role = await session.get(Role, role_id)
    if not role:
        raise AppError("NOT_FOUND", "Role not found.", status_code=404)

    await session.execute(
        RolePermission.__table__.delete().where(RolePermission.role_id == role_id)
    )
    await session.execute(
        UserRole.__table__.delete().where(UserRole.role_id == role_id)
    )
    await session.delete(role)
    await session.commit()
    logger.info("rbac.role_deleted", role_id=str(role_id))


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


async def list_permissions(
    session: AsyncSession, page: int = 1, page_size: int = 100
) -> PagedResponse[PermissionResponse]:
    total = (await session.execute(select(func.count()).select_from(Permission))).scalar_one()
    perms = (
        await session.execute(
            select(Permission)
            .order_by(Permission.name)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).scalars().all()
    return paginate(
        [PermissionResponse.model_validate(p, from_attributes=True) for p in perms],
        total,
        page,
        page_size,
    )


async def create_permission(
    data: PermissionCreateRequest, session: AsyncSession
) -> PermissionResponse:
    existing = await session.execute(select(Permission).where(Permission.name == data.name))
    if existing.scalar_one_or_none():
        raise AppError("CONFLICT", f"Permission '{data.name}' already exists.", status_code=409)

    perm = Permission(name=data.name, description=data.description)
    session.add(perm)
    await session.commit()
    await session.refresh(perm)
    logger.info("rbac.permission_created", permission_id=str(perm.id), name=perm.name)
    return PermissionResponse.model_validate(perm, from_attributes=True)


async def delete_permission(permission_id: uuid.UUID, session: AsyncSession) -> None:
    perm = await session.get(Permission, permission_id)
    if not perm:
        raise AppError("NOT_FOUND", "Permission not found.", status_code=404)

    await session.execute(
        RolePermission.__table__.delete().where(RolePermission.permission_id == permission_id)
    )
    await session.delete(perm)
    await session.commit()
    logger.info("rbac.permission_deleted", permission_id=str(permission_id))


# ---------------------------------------------------------------------------
# Role ↔ Permission assignments
# ---------------------------------------------------------------------------


async def assign_permission_to_role(
    role_id: uuid.UUID, permission_id: uuid.UUID, session: AsyncSession
) -> RoleDetailResponse:
    role = await session.get(Role, role_id)
    if not role:
        raise AppError("NOT_FOUND", "Role not found.", status_code=404)

    perm = await session.get(Permission, permission_id)
    if not perm:
        raise AppError("NOT_FOUND", "Permission not found.", status_code=404)

    existing = await session.get(RolePermission, {"role_id": role_id, "permission_id": permission_id})
    if not existing:
        session.add(RolePermission(role_id=role_id, permission_id=permission_id))
        await session.commit()
        logger.info("rbac.permission_assigned", role_id=str(role_id), permission_id=str(permission_id))

    return await get_role(role_id, session)


async def remove_permission_from_role(
    role_id: uuid.UUID, permission_id: uuid.UUID, session: AsyncSession
) -> None:
    rp = await session.get(RolePermission, {"role_id": role_id, "permission_id": permission_id})
    if not rp:
        raise AppError("NOT_FOUND", "Assignment not found.", status_code=404)

    await session.delete(rp)
    await session.commit()
    logger.info("rbac.permission_removed", role_id=str(role_id), permission_id=str(permission_id))


# ---------------------------------------------------------------------------
# User ↔ Role assignments
# ---------------------------------------------------------------------------


async def assign_role_to_user(
    user_id: uuid.UUID, role_id: uuid.UUID, session: AsyncSession
) -> UserRolesResponse:
    user = await session.get(User, user_id)
    if not user or user.deleted_at is not None:
        raise AppError("NOT_FOUND", "User not found.", status_code=404)

    role = await session.get(Role, role_id)
    if not role:
        raise AppError("NOT_FOUND", "Role not found.", status_code=404)

    existing = await session.get(UserRole, {"user_id": user_id, "role_id": role_id})
    if not existing:
        session.add(UserRole(user_id=user_id, role_id=role_id))
        await session.commit()
        logger.info("rbac.role_assigned", user_id=str(user_id), role_id=str(role_id))

    return await get_user_roles(user_id, session)


async def remove_role_from_user(
    user_id: uuid.UUID, role_id: uuid.UUID, session: AsyncSession
) -> None:
    ur = await session.get(UserRole, {"user_id": user_id, "role_id": role_id})
    if not ur:
        raise AppError("NOT_FOUND", "Assignment not found.", status_code=404)

    await session.delete(ur)
    await session.commit()
    logger.info("rbac.role_removed", user_id=str(user_id), role_id=str(role_id))


async def get_user_roles(user_id: uuid.UUID, session: AsyncSession) -> UserRolesResponse:
    user = await session.get(User, user_id)
    if not user or user.deleted_at is not None:
        raise AppError("NOT_FOUND", "User not found.", status_code=404)

    roles_result = await session.execute(
        select(Role)
        .join(UserRole, Role.id == UserRole.role_id)
        .where(UserRole.user_id == user_id)
        .order_by(Role.name)
    )
    roles = roles_result.scalars().all()

    perms_result = await session.execute(
        select(Permission)
        .join(RolePermission, Permission.id == RolePermission.permission_id)
        .join(Role, Role.id == RolePermission.role_id)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
        .distinct()
        .order_by(Permission.name)
    )
    perms = perms_result.scalars().all()

    return UserRolesResponse(
        user_id=user_id,
        roles=[RoleResponse.model_validate(r, from_attributes=True) for r in roles],
        permissions=[PermissionResponse.model_validate(p, from_attributes=True) for p in perms],
    )
