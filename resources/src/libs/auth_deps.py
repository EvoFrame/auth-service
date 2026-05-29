"""Shared FastAPI auth dependencies."""

import uuid

import jwt as _jwt
import structlog
from fastapi import Depends, Header
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.db.session import get_session
from src.libs.errors import AppError
from src.models.rbac import Permission, Role, RolePermission, UserRole
from src.models.user import User

logger = structlog.get_logger()


async def get_current_user(
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Resolve the authenticated user from the bearer token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise AppError("MISSING_TOKEN", "Authorization header required.", status_code=401)

    raw = authorization.removeprefix("Bearer ")
    try:
        payload = _jwt.decode(raw, settings.RS256_PUBLIC_KEY, algorithms=["RS256"])
    except _jwt.ExpiredSignatureError:
        raise AppError("TOKEN_EXPIRED", "Access token expired.", status_code=401)
    except _jwt.InvalidTokenError:
        raise AppError("INVALID_TOKEN", "Invalid access token.", status_code=401)

    if payload.get("type") != "user":
        raise AppError("INVALID_TOKEN", "Not a user token.", status_code=401)

    user = await session.get(User, uuid.UUID(payload["sub"]))
    if not user or not user.is_active or user.deleted_at is not None:
        raise AppError("USER_NOT_FOUND", "User not found or disabled.", status_code=404)
    return user


async def _load_user_permissions(user_id: uuid.UUID, session: AsyncSession) -> set[str]:
    result = await session.execute(
        select(Permission.name)
        .join(RolePermission, Permission.id == RolePermission.permission_id)
        .join(Role, Role.id == RolePermission.role_id)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
        .distinct()
    )
    return {row[0] for row in result.all()}


def require_permission(*required: str):
    """Dependency factory — user must hold ALL listed permissions."""

    async def _dep(
        user: User = Depends(get_current_user),
        session: AsyncSession = Depends(get_session),
    ) -> User:
        perms = await _load_user_permissions(user.id, session)
        missing = [p for p in required if p not in perms]
        if missing:
            raise AppError(
                "FORBIDDEN",
                f"Missing required permissions: {', '.join(missing)}",
                status_code=403,
            )
        return user

    return _dep
