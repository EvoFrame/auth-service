"""RBAC management router — roles, permissions, and assignments."""

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.controllers import rbac_mgmt as rbac_ctrl
from src.db.session import get_session
from src.libs.auth_deps import require_permission
from src.libs.pagination import PagedResponse
from src.schemas.rbac_mgmt import (
    PermissionCreateRequest,
    PermissionResponse,
    RoleCreateRequest,
    RoleDetailResponse,
    RoleResponse,
    RoleUpdateRequest,
    UserRolesResponse,
)

_read = Depends(require_permission("roles:read"))
_write = Depends(require_permission("roles:write"))

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

_roles_router = APIRouter(prefix="/roles", tags=["[RBAC] Roles"])


@_roles_router.get("", response_model=PagedResponse[RoleResponse], dependencies=[_read])
async def list_roles(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
) -> PagedResponse[RoleResponse]:
    return await rbac_ctrl.list_roles(session, page=page, page_size=page_size)


@_roles_router.post("", response_model=RoleResponse, status_code=201, dependencies=[_write])
async def create_role(
    data: RoleCreateRequest,
    session: AsyncSession = Depends(get_session),
) -> RoleResponse:
    return await rbac_ctrl.create_role(data, session)


@_roles_router.get("/{role_id}", response_model=RoleDetailResponse, dependencies=[_read])
async def get_role(
    role_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> RoleDetailResponse:
    return await rbac_ctrl.get_role(role_id, session)


@_roles_router.patch("/{role_id}", response_model=RoleResponse, dependencies=[_write])
async def update_role(
    role_id: uuid.UUID,
    data: RoleUpdateRequest,
    session: AsyncSession = Depends(get_session),
) -> RoleResponse:
    return await rbac_ctrl.update_role(role_id, data, session)


@_roles_router.delete("/{role_id}", status_code=204, dependencies=[_write])
async def delete_role(
    role_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> None:
    await rbac_ctrl.delete_role(role_id, session)


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------

_permissions_router = APIRouter(prefix="/permissions", tags=["[RBAC] Permissions"])


@_permissions_router.get("", response_model=PagedResponse[PermissionResponse], dependencies=[_read])
async def list_permissions(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
) -> PagedResponse[PermissionResponse]:
    return await rbac_ctrl.list_permissions(session, page=page, page_size=page_size)


@_permissions_router.post("", response_model=PermissionResponse, status_code=201, dependencies=[_write])
async def create_permission(
    data: PermissionCreateRequest,
    session: AsyncSession = Depends(get_session),
) -> PermissionResponse:
    return await rbac_ctrl.create_permission(data, session)


@_permissions_router.delete("/{permission_id}", status_code=204, dependencies=[_write])
async def delete_permission(
    permission_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> None:
    await rbac_ctrl.delete_permission(permission_id, session)


# ---------------------------------------------------------------------------
# Role ↔ Permission assignments
# ---------------------------------------------------------------------------

_role_permissions_router = APIRouter(tags=["[RBAC] Role Permissions"])


@_role_permissions_router.post(
    "/roles/{role_id}/permissions/{permission_id}",
    response_model=RoleDetailResponse,
    dependencies=[_write],
)
async def assign_permission_to_role(
    role_id: uuid.UUID,
    permission_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> RoleDetailResponse:
    return await rbac_ctrl.assign_permission_to_role(role_id, permission_id, session)


@_role_permissions_router.delete(
    "/roles/{role_id}/permissions/{permission_id}",
    status_code=204,
    dependencies=[_write],
)
async def remove_permission_from_role(
    role_id: uuid.UUID,
    permission_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> None:
    await rbac_ctrl.remove_permission_from_role(role_id, permission_id, session)


# ---------------------------------------------------------------------------
# User ↔ Role assignments
# ---------------------------------------------------------------------------

_user_roles_router = APIRouter(prefix="/users", tags=["[RBAC] User Roles"])


@_user_roles_router.get("/{user_id}/roles", response_model=UserRolesResponse, dependencies=[_read])
async def get_user_roles(
    user_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> UserRolesResponse:
    return await rbac_ctrl.get_user_roles(user_id, session)


@_user_roles_router.post(
    "/{user_id}/roles/{role_id}",
    response_model=UserRolesResponse,
    dependencies=[_write],
)
async def assign_role_to_user(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> UserRolesResponse:
    return await rbac_ctrl.assign_role_to_user(user_id, role_id, session)


@_user_roles_router.delete(
    "/{user_id}/roles/{role_id}",
    status_code=204,
    dependencies=[_write],
)
async def remove_role_from_user(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> None:
    await rbac_ctrl.remove_role_from_user(user_id, role_id, session)


# ---------------------------------------------------------------------------
# Main RBAC router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/rbac")
router.include_router(_roles_router)
router.include_router(_permissions_router)
router.include_router(_role_permissions_router)
router.include_router(_user_roles_router)
