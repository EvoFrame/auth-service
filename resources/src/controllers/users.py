"""Users controller — auth flows + CRUD."""

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import structlog
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.events.publisher import EventPublisher
from src.libs.errors import AppError
from src.libs.pagination import PagedResponse, paginate
from src.models.rbac import Permission, Role, RolePermission, UserRole
from src.models.session import RefreshSession
from src.models.user import User
from src.schemas.rbac import PermissionsResponse
from src.schemas.users import (
    IntrospectResponse,
    LoginRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
    UserSelfUpdateRequest,
    UserUpdateRequest,
    VerifyEmailRequest,
)

logger = structlog.get_logger()

_ph = PasswordHasher(
    time_cost=settings.ARGON2_TIME_COST,
    memory_cost=settings.ARGON2_MEMORY_COST,
    parallelism=settings.ARGON2_PARALLELISM,
)

# Redis key templates
_REFRESH_KEY = "refresh:{jti}"
_VERIFY_KEY = "email_verify:{token}"
_RESET_KEY = "pwd_reset:{token}"

_VERIFY_TTL = 86400  # 24 h
_RESET_TTL = 3600  # 1 h


# ── Helpers (also imported by oauth controller) ───────────────────────────────


def _issue_access_token(user: User, roles: list[str]) -> tuple[str, str]:
    """Return (encoded_jwt, jti)."""
    jti = str(uuid.uuid4())
    now = datetime.now(UTC)
    payload = {
        "jti": jti,
        "sub": str(user.id),
        "email": user.email,
        "roles": roles,
        "type": "user",
        "iss": settings.SERVICE_ID,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.ACCESS_TOKEN_TTL)).timestamp()),
    }
    token = jwt.encode(payload, settings.RS256_PRIVATE_KEY, algorithm="RS256")
    return token, jti


async def _get_user_roles(user_id: uuid.UUID, session: AsyncSession) -> list[str]:
    result = await session.execute(
        select(Role).join(UserRole, Role.id == UserRole.role_id).where(UserRole.user_id == user_id)
    )
    return [r.name for r in result.scalars().all()]


async def _verify_totp(user: User, code: str) -> None:
    import pyotp
    from cryptography.fernet import Fernet

    if not user.totp_secret_enc or not settings.TOTP_ENCRYPTION_KEY:
        raise AppError("MFA_NOT_CONFIGURED", "MFA is not configured for this account.", status_code=403)

    f = Fernet(settings.TOTP_ENCRYPTION_KEY.encode())
    secret = f.decrypt(user.totp_secret_enc.encode()).decode()
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        raise AppError("INVALID_TOTP", "Invalid TOTP code.", status_code=401)


# ── Auth flows ────────────────────────────────────────────────────────────────


async def register(
    body: RegisterRequest,
    session: AsyncSession,
    redis,
    publisher: EventPublisher,
) -> dict:
    existing = (await session.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if existing:
        raise AppError("EMAIL_TAKEN", "Email is already registered.", status_code=409)

    password_hash = _ph.hash(body.password)
    user = User(email=body.email, password_hash=password_hash)
    session.add(user)
    await session.commit()
    await session.refresh(user)

    verify_token = secrets.token_urlsafe(32)
    await redis.setex(_VERIFY_KEY.format(token=verify_token), _VERIFY_TTL, str(user.id))

    await publisher.publish(
        "auth.user.registered",
        {"user_id": str(user.id), "email": user.email, "verify_token": verify_token},
    )
    logger.info("user_registered", user_id=str(user.id))
    return {"user_id": str(user.id), "message": "Registration successful. Please verify your email."}


async def login(
    body: LoginRequest,
    session: AsyncSession,
    redis,
    request: Request,
) -> TokenResponse:
    user = (await session.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if not user or user.deleted_at is not None:
        raise AppError("INVALID_CREDENTIALS", "Invalid email or password.", status_code=401)

    try:
        _ph.verify(user.password_hash, body.password)
    except VerifyMismatchError:
        raise AppError("INVALID_CREDENTIALS", "Invalid email or password.", status_code=401)

    if not user.is_active:
        raise AppError("ACCOUNT_DISABLED", "This account has been disabled.", status_code=403)

    if not user.is_verified:
        raise AppError("EMAIL_NOT_VERIFIED", "Please verify your email before logging in.", status_code=403)

    if user.mfa_enabled:
        if not body.totp_code:
            raise AppError("MFA_REQUIRED", "TOTP code required.", status_code=403)
        await _verify_totp(user, body.totp_code)

    roles = await _get_user_roles(user.id, session)
    access_token, _ = _issue_access_token(user, roles)

    refresh_jti = str(uuid.uuid4())  # noqa: F841 — reserved for future audit event
    raw_refresh = secrets.token_urlsafe(48)
    refresh_hash = _ph.hash(raw_refresh)
    expires_at = datetime.now(UTC) + timedelta(seconds=settings.REFRESH_TOKEN_TTL)

    rs = RefreshSession(
        user_id=user.id,
        token_hash=refresh_hash,
        expires_at=expires_at,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    session.add(rs)
    await session.commit()

    await redis.setex(
        _REFRESH_KEY.format(jti=str(rs.id)),
        settings.REFRESH_TOKEN_TTL,
        str(rs.id),
    )

    composite_refresh = f"{rs.id}:{raw_refresh}"
    return TokenResponse(
        access_token=access_token,
        refresh_token=composite_refresh,
        expires_in=settings.ACCESS_TOKEN_TTL,
    )


async def refresh_token(
    body: RefreshRequest,
    session: AsyncSession,
    redis,
) -> TokenResponse:
    try:
        session_id, raw_token = body.refresh_token.split(":", 1)
    except ValueError:
        raise AppError("INVALID_REFRESH_TOKEN", "Invalid refresh token format.", status_code=401)

    rs = (
        await session.execute(
            select(RefreshSession).where(
                RefreshSession.id == uuid.UUID(session_id),
                RefreshSession.revoked_at.is_(None),
            )
        )
    ).scalar_one_or_none()

    if not rs:
        raise AppError("INVALID_REFRESH_TOKEN", "Refresh token not found or revoked.", status_code=401)

    if rs.expires_at.replace(tzinfo=UTC) < datetime.now(UTC):
        raise AppError("REFRESH_TOKEN_EXPIRED", "Refresh token has expired.", status_code=401)

    try:
        _ph.verify(rs.token_hash, raw_token)
    except VerifyMismatchError:
        raise AppError("INVALID_REFRESH_TOKEN", "Invalid refresh token.", status_code=401)

    rs.revoked_at = datetime.now(UTC)
    await redis.delete(_REFRESH_KEY.format(jti=session_id))

    user = await session.get(User, rs.user_id)
    if not user or not user.is_active or user.deleted_at is not None:
        raise AppError("ACCOUNT_DISABLED", "Account not found or disabled.", status_code=403)

    roles = await _get_user_roles(user.id, session)
    access_token, _ = _issue_access_token(user, roles)

    new_refresh_raw = secrets.token_urlsafe(48)
    new_rs = RefreshSession(
        user_id=user.id,
        token_hash=_ph.hash(new_refresh_raw),
        expires_at=datetime.now(UTC) + timedelta(seconds=settings.REFRESH_TOKEN_TTL),
    )
    session.add(new_rs)
    await session.commit()

    await redis.setex(
        _REFRESH_KEY.format(jti=str(new_rs.id)),
        settings.REFRESH_TOKEN_TTL,
        str(new_rs.id),
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=f"{new_rs.id}:{new_refresh_raw}",
        expires_in=settings.ACCESS_TOKEN_TTL,
    )


async def logout(refresh_token_str: str, session: AsyncSession, redis) -> dict:
    try:
        session_id, raw_token = refresh_token_str.split(":", 1)
        session_uuid = uuid.UUID(session_id)
    except ValueError:
        return {"message": "Logged out successfully."}

    rs = (
        await session.execute(
            select(RefreshSession).where(
                RefreshSession.id == session_uuid,
                RefreshSession.revoked_at.is_(None),
            )
        )
    ).scalar_one_or_none()

    if rs:
        rs.revoked_at = datetime.now(UTC)
        await redis.delete(_REFRESH_KEY.format(jti=session_id))
        await session.commit()

    return {"message": "Logged out successfully."}


async def introspect(authorization: str | None) -> IntrospectResponse:
    if not authorization or not authorization.startswith("Bearer "):
        raise AppError("MISSING_TOKEN", "Authorization header missing.", status_code=401)

    raw_token = authorization.removeprefix("Bearer ")
    try:
        payload = jwt.decode(
            raw_token,
            settings.RS256_PUBLIC_KEY,
            algorithms=["RS256"],
        )
    except jwt.ExpiredSignatureError:
        raise AppError("TOKEN_EXPIRED", "Access token has expired.", status_code=401)
    except jwt.InvalidTokenError:
        raise AppError("INVALID_TOKEN", "Invalid access token.", status_code=401)

    if payload.get("type") != "user":
        raise AppError("INVALID_TOKEN", "Not a user token.", status_code=401)

    return IntrospectResponse(
        sub=payload["sub"],
        email=payload["email"],
        roles=payload.get("roles", []),
        exp=payload["exp"],
        iat=payload["iat"],
        jti=payload["jti"],
        type=payload["type"],
    )


async def get_permissions(user_id: str, session: AsyncSession) -> PermissionsResponse:
    uid = uuid.UUID(user_id)
    roles_result = await session.execute(
        select(Role).join(UserRole, Role.id == UserRole.role_id).where(UserRole.user_id == uid)
    )
    roles = roles_result.scalars().all()
    role_names = [r.name for r in roles]
    role_ids = [r.id for r in roles]

    perms_result = await session.execute(
        select(Permission)
        .join(RolePermission, Permission.id == RolePermission.permission_id)
        .where(RolePermission.role_id.in_(role_ids))
        .distinct()
    )
    permissions = [p.name for p in perms_result.scalars().all()]

    return PermissionsResponse(user_id=user_id, roles=role_names, permissions=permissions)


async def verify_email(body: VerifyEmailRequest, session: AsyncSession, redis) -> dict:
    key = _VERIFY_KEY.format(token=body.token)
    user_id_str = await redis.get(key)
    if not user_id_str:
        raise AppError("INVALID_TOKEN", "Email verification token is invalid or expired.", status_code=400)

    user = await session.get(User, uuid.UUID(user_id_str))
    if not user:
        raise AppError("USER_NOT_FOUND", "User not found.", status_code=404)

    user.is_verified = True
    await redis.delete(key)
    await session.commit()
    return {"message": "Email verified successfully."}


async def password_reset_request(
    body: PasswordResetRequest,
    session: AsyncSession,
    redis,
    publisher: EventPublisher,
) -> dict:
    user = (await session.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    # Always return success to avoid user enumeration
    if not user:
        return {"message": "If that email exists, a reset link has been sent."}

    reset_token = secrets.token_urlsafe(32)
    await redis.setex(_RESET_KEY.format(token=reset_token), _RESET_TTL, str(user.id))

    await publisher.publish(
        "auth.user.password_reset_requested",
        {"user_id": str(user.id), "email": user.email, "reset_token": reset_token},
    )
    return {"message": "If that email exists, a reset link has been sent."}


async def password_reset_confirm(
    body: PasswordResetConfirm,
    session: AsyncSession,
    redis,
    publisher: EventPublisher,
) -> dict:
    key = _RESET_KEY.format(token=body.token)
    user_id_str = await redis.get(key)
    if not user_id_str:
        raise AppError("INVALID_TOKEN", "Password reset token is invalid or expired.", status_code=400)

    user = await session.get(User, uuid.UUID(user_id_str))
    if not user:
        raise AppError("USER_NOT_FOUND", "User not found.", status_code=404)

    user.password_hash = _ph.hash(body.new_password)
    await redis.delete(key)

    # Revoke all active refresh sessions — force re-login after password change
    active_sessions_result = await session.execute(
        select(RefreshSession).where(
            RefreshSession.user_id == user.id,
            RefreshSession.revoked_at.is_(None),
        )
    )
    now = datetime.now(UTC)
    for rs in active_sessions_result.scalars().all():
        rs.revoked_at = now
        await redis.delete(_REFRESH_KEY.format(jti=str(rs.id)))

    await session.commit()

    await publisher.publish("auth.user.password_reset", {"user_id": str(user.id), "email": user.email})
    return {"message": "Password reset successfully."}


# ── Self-service ──────────────────────────────────────────────────────────────


def get_me(user: User) -> UserResponse:
    return UserResponse.model_validate(user)


async def update_me(user: User, body: UserSelfUpdateRequest, session: AsyncSession) -> UserResponse:
    if body.email is not None:
        conflict = (
            await session.execute(
                select(User).where(User.email == body.email, User.id != user.id)
            )
        ).scalar_one_or_none()
        if conflict:
            raise AppError("EMAIL_TAKEN", "Email is already registered.", status_code=409)
        user.email = body.email

    await session.commit()
    await session.refresh(user)
    return UserResponse.model_validate(user)


async def delete_user(user: User, session: AsyncSession, redis, publisher: EventPublisher) -> dict:
    if user.deleted_at is not None:
        raise AppError("USER_ALREADY_DELETED", "User account is already deleted.", status_code=409)

    now = datetime.now(UTC)

    active_sessions_result = await session.execute(
        select(RefreshSession).where(
            RefreshSession.user_id == user.id,
            RefreshSession.revoked_at.is_(None),
        )
    )
    for rs in active_sessions_result.scalars().all():
        rs.revoked_at = now
        await redis.delete(_REFRESH_KEY.format(jti=str(rs.id)))

    user.deleted_at = now
    await session.commit()

    await publisher.publish("auth.user.deleted", {"user_id": str(user.id), "email": user.email})
    logger.info("user_deleted", user_id=str(user.id))
    return {"message": "User account deleted successfully."}


# ── Admin CRUD ────────────────────────────────────────────────────────────────


async def list_users(
    session: AsyncSession,
    page: int,
    page_size: int,
    include_deleted: bool = False,
) -> PagedResponse[UserResponse]:
    base_q = select(User)
    count_q = select(func.count()).select_from(User)
    if not include_deleted:
        base_q = base_q.where(User.deleted_at.is_(None))
        count_q = count_q.where(User.deleted_at.is_(None))

    total = (await session.execute(count_q)).scalar_one()
    users = (
        await session.execute(base_q.offset((page - 1) * page_size).limit(page_size))
    ).scalars().all()

    return paginate([UserResponse.model_validate(u) for u in users], total, page, page_size)


async def get_user(user_id: str, session: AsyncSession) -> UserResponse:
    user = await session.get(User, uuid.UUID(user_id))
    if not user:
        raise AppError("USER_NOT_FOUND", "User not found.", status_code=404)
    return UserResponse.model_validate(user)


async def update_user(user_id: str, body: UserUpdateRequest, session: AsyncSession) -> UserResponse:
    user = await session.get(User, uuid.UUID(user_id))
    if not user:
        raise AppError("USER_NOT_FOUND", "User not found.", status_code=404)
    if user.deleted_at is not None:
        raise AppError("USER_DELETED", "Cannot update a deleted user.", status_code=409)

    if body.email is not None:
        conflict = (
            await session.execute(
                select(User).where(User.email == body.email, User.id != user.id)
            )
        ).scalar_one_or_none()
        if conflict:
            raise AppError("EMAIL_TAKEN", "Email is already registered.", status_code=409)
        user.email = body.email

    if body.is_active is not None:
        user.is_active = body.is_active
    if body.is_verified is not None:
        user.is_verified = body.is_verified

    await session.commit()
    await session.refresh(user)
    return UserResponse.model_validate(user)


async def admin_delete_user(
    user_id: str,
    session: AsyncSession,
    redis,
    publisher: EventPublisher,
) -> dict:
    user = await session.get(User, uuid.UUID(user_id))
    if not user:
        raise AppError("USER_NOT_FOUND", "User not found.", status_code=404)
    return await delete_user(user, session, redis, publisher)
