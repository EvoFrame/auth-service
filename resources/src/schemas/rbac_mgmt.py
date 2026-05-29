"""Schemas for RBAC management endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel


class RoleCreateRequest(BaseModel):
    name: str
    description: str | None = None


class RoleUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None


class PermissionResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    created_at: datetime


class RoleResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    created_at: datetime


class RoleDetailResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    created_at: datetime
    permissions: list[PermissionResponse]


class PermissionCreateRequest(BaseModel):
    name: str
    description: str | None = None


class UserRolesResponse(BaseModel):
    user_id: uuid.UUID
    roles: list[RoleResponse]
    permissions: list[PermissionResponse]
