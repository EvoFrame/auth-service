import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr

# ── Auth flows ────────────────────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    totp_code: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class IntrospectResponse(BaseModel):
    sub: str
    email: str
    roles: list[str]
    exp: int
    iat: int
    jti: str
    type: str


class VerifyEmailRequest(BaseModel):
    token: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str


# ── CRUD ──────────────────────────────────────────────────────────────────────


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None

    model_config = {"from_attributes": True}


class UserSelfUpdateRequest(BaseModel):
    """Fields a user may update on their own account."""

    email: EmailStr | None = None


class UserUpdateRequest(BaseModel):
    """Fields an admin may update on any account."""

    email: EmailStr | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
