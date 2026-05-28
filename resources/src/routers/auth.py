"""Auth router — wires all endpoints from the service spec."""

import uuid

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.controllers import auth as auth_ctrl
from src.controllers import mfa as mfa_ctrl
from src.controllers import oauth as oauth_ctrl
from src.controllers import service as service_ctrl
from src.db.session import get_session
from src.events.publisher import EventPublisher
from src.libs.errors import AppError
from src.models.user import User
from src.redis.client import get_redis
from src.schemas.auth import (
    IntrospectResponse,
    LoginRequest,
    LogoutRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    VerifyEmailRequest,
)
from src.schemas.mfa import MFADisableRequest, MFAEnableResponse, MFAVerifyRequest
from src.schemas.rbac import PermissionsResponse
from src.schemas.service import (
    ServiceIntrospectRequest,
    ServiceIntrospectResponse,
    ServiceTokenRequest,
    ServiceTokenResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


async def _get_publisher(redis=Depends(get_redis)) -> EventPublisher:
    return EventPublisher(redis)


async def _get_current_user(
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Resolve the authenticated user from the bearer token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise AppError("MISSING_TOKEN", "Authorization header required.", status_code=401)

    import jwt as _jwt

    from src.config.settings import settings

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
    if not user or not user.is_active:
        raise AppError("USER_NOT_FOUND", "User not found or disabled.", status_code=404)
    return user


# ── Registration & login ──────────────────────────────────────────────────────


@router.post("/register", status_code=201)
async def register(
    body: RegisterRequest,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
    publisher: EventPublisher = Depends(_get_publisher),
):
    return await auth_ctrl.register(body, session, redis, publisher)


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
):
    return await auth_ctrl.login(body, session, redis, request)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
):
    return await auth_ctrl.refresh_token(body, session, redis)


@router.post("/logout")
async def logout(
    body: LogoutRequest,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
):
    return await auth_ctrl.logout(body.refresh_token, session, redis)


# ── Token introspection ───────────────────────────────────────────────────────


@router.get("/introspect", response_model=IntrospectResponse)
async def introspect(authorization: str | None = Header(default=None)):
    return await auth_ctrl.introspect(authorization)


@router.get("/permissions/{user_id}", response_model=PermissionsResponse)
async def permissions(user_id: str, session: AsyncSession = Depends(get_session)):
    return await auth_ctrl.get_permissions(user_id, session)


# ── Email & password ──────────────────────────────────────────────────────────


@router.post("/verify-email")
async def verify_email(
    body: VerifyEmailRequest,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
):
    return await auth_ctrl.verify_email(body, session, redis)


@router.post("/password-reset/request")
async def password_reset_request(
    body: PasswordResetRequest,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
    publisher: EventPublisher = Depends(_get_publisher),
):
    return await auth_ctrl.password_reset_request(body, session, redis, publisher)


@router.post("/password-reset/confirm")
async def password_reset_confirm(
    body: PasswordResetConfirm,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
    publisher: EventPublisher = Depends(_get_publisher),
):
    return await auth_ctrl.password_reset_confirm(body, session, redis, publisher)


# ── MFA ───────────────────────────────────────────────────────────────────────


@router.post("/mfa/enable", response_model=MFAEnableResponse)
async def mfa_enable(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(_get_current_user),
):
    return await mfa_ctrl.mfa_enable(user, session)


@router.post("/mfa/verify")
async def mfa_verify(
    body: MFAVerifyRequest,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
    publisher: EventPublisher = Depends(_get_publisher),
    user: User = Depends(_get_current_user),
):
    return await mfa_ctrl.mfa_verify_and_activate(user, body, session, publisher)


@router.post("/mfa/disable")
async def mfa_disable(
    body: MFADisableRequest,
    session: AsyncSession = Depends(get_session),
    publisher: EventPublisher = Depends(_get_publisher),
    user: User = Depends(_get_current_user),
):
    return await mfa_ctrl.mfa_disable(user, body, session, publisher)


# ── Service (M2M) tokens ──────────────────────────────────────────────────────


@router.post("/service/token", response_model=ServiceTokenResponse)
async def service_token(
    body: ServiceTokenRequest,
    session: AsyncSession = Depends(get_session),
    publisher: EventPublisher = Depends(_get_publisher),
):
    return await service_ctrl.issue_service_token(body, session, publisher)


@router.post("/service/introspect", response_model=ServiceIntrospectResponse)
async def service_introspect(body: ServiceIntrospectRequest):
    return await service_ctrl.introspect_service_token(body)


# ── OAuth2 ────────────────────────────────────────────────────────────────────


@router.post("/oauth/{provider}")
async def oauth_login(
    provider: str,
    code: str,
    session: AsyncSession = Depends(get_session),
):
    return await oauth_ctrl.oauth_login(provider, code, session)
