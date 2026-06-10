"""Users router — auth flows, self-service, and admin CRUD."""

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.controllers import mfa as mfa_ctrl
from src.controllers import oauth as oauth_ctrl
from src.controllers import users as users_ctrl
from src.db.session import get_session
from src.events.publisher import EventPublisher
from src.libs.auth_deps import get_current_user, require_permission
from src.libs.pagination import PagedResponse
from src.models.user import User
from src.redis.client import get_redis
from src.schemas.mfa import MFADisableRequest, MFAEnableResponse, MFAVerifyRequest
from src.schemas.rbac import PermissionsResponse
from src.schemas.users import (
    IntrospectResponse,
    LoginRequest,
    LogoutRequest,
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


async def _get_publisher(redis=Depends(get_redis)) -> EventPublisher:
    return EventPublisher(redis)


# ── Registration & login ──────────────────────────────────────────────────────

_auth_router = APIRouter(prefix="/users", tags=["Authentication"])


@_auth_router.post("/register", status_code=201)
async def register(
    body: RegisterRequest,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
    publisher: EventPublisher = Depends(_get_publisher),
):
    return await users_ctrl.register(body, session, redis, publisher)


@_auth_router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
):
    return await users_ctrl.login(body, session, redis, request)


@_auth_router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
):
    return await users_ctrl.refresh_token(body, session, redis)


@_auth_router.post("/logout")
async def logout(
    body: LogoutRequest,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
):
    return await users_ctrl.logout(body.refresh_token, session, redis, body.access_token)


@_auth_router.get("/introspect", response_model=IntrospectResponse)
async def introspect(authorization: str | None = Header(default=None)):
    return await users_ctrl.introspect(authorization)


@_auth_router.get("/permissions/{user_id}", response_model=PermissionsResponse)
async def permissions(user_id: str, session: AsyncSession = Depends(get_session)):
    return await users_ctrl.get_permissions(user_id, session)


@_auth_router.post("/verify-email")
async def verify_email(
    body: VerifyEmailRequest,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
):
    return await users_ctrl.verify_email(body, session, redis)


@_auth_router.post("/password-reset/request")
async def password_reset_request(
    body: PasswordResetRequest,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
    publisher: EventPublisher = Depends(_get_publisher),
):
    return await users_ctrl.password_reset_request(body, session, redis, publisher)


@_auth_router.post("/password-reset/confirm")
async def password_reset_confirm(
    body: PasswordResetConfirm,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
    publisher: EventPublisher = Depends(_get_publisher),
):
    return await users_ctrl.password_reset_confirm(body, session, redis, publisher)


# ── Self-service (/me) ────────────────────────────────────────────────────────

_account_router = APIRouter(prefix="/users/me", tags=["Account"])


@_account_router.get("", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)):
    return users_ctrl.get_me(user)


@_account_router.patch("", response_model=UserResponse)
async def update_me(
    body: UserSelfUpdateRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
):
    return await users_ctrl.update_me(user, body, session)


@_account_router.delete("", status_code=200)
async def delete_me(
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
    publisher: EventPublisher = Depends(_get_publisher),
    user: User = Depends(get_current_user),
):
    return await users_ctrl.delete_user(user, session, redis, publisher)


# ── MFA ───────────────────────────────────────────────────────────────────────

_mfa_router = APIRouter(prefix="/users/me/mfa", tags=["MFA"])


@_mfa_router.post("/enable", response_model=MFAEnableResponse)
async def mfa_enable(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
):
    return await mfa_ctrl.mfa_enable(user, session)


@_mfa_router.post("/verify")
async def mfa_verify(
    body: MFAVerifyRequest,
    session: AsyncSession = Depends(get_session),
    publisher: EventPublisher = Depends(_get_publisher),
    user: User = Depends(get_current_user),
):
    return await mfa_ctrl.mfa_verify_and_activate(user, body, session, publisher)


@_mfa_router.post("/disable")
async def mfa_disable(
    body: MFADisableRequest,
    session: AsyncSession = Depends(get_session),
    publisher: EventPublisher = Depends(_get_publisher),
    user: User = Depends(get_current_user),
):
    return await mfa_ctrl.mfa_disable(user, body, session, publisher)


# ── OAuth2 ────────────────────────────────────────────────────────────────────

_oauth_router = APIRouter(prefix="/users/oauth", tags=["OAuth"])


@_oauth_router.post("/{provider}")
async def oauth_login(
    provider: str,
    code: str,
    session: AsyncSession = Depends(get_session),
):
    return await oauth_ctrl.oauth_login(provider, code, session)


# ── Admin CRUD ────────────────────────────────────────────────────────────────

_admin_users_router = APIRouter(prefix="/users", tags=["Admin — Users"])


@_admin_users_router.get("", response_model=PagedResponse[UserResponse])
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    include_deleted: bool = Query(False),
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_permission("users:read")),
):
    return await users_ctrl.list_users(session, page, page_size, include_deleted)


@_admin_users_router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_permission("users:read")),
):
    return await users_ctrl.get_user(user_id, session)


@_admin_users_router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    body: UserUpdateRequest,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_permission("users:write")),
):
    return await users_ctrl.update_user(user_id, body, session)


@_admin_users_router.delete("/{user_id}", status_code=200)
async def admin_delete_user(
    user_id: str,
    session: AsyncSession = Depends(get_session),
    redis=Depends(get_redis),
    publisher: EventPublisher = Depends(_get_publisher),
    _: User = Depends(require_permission("users:write")),
):
    return await users_ctrl.admin_delete_user(user_id, session, redis, publisher)


# ── Main users router ─────────────────────────────────────────────────────────

router = APIRouter()
router.include_router(_auth_router)
router.include_router(_account_router)
router.include_router(_mfa_router)
router.include_router(_oauth_router)
router.include_router(_admin_users_router)
