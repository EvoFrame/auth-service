import uuid
from datetime import datetime

from pydantic import BaseModel

# ── Auth flows ────────────────────────────────────────────────────────────────


class ServiceTokenRequest(BaseModel):
    service_id: str
    service_secret: str


class ServiceTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class ServiceIntrospectRequest(BaseModel):
    token: str


class ServiceIntrospectResponse(BaseModel):
    sub: str
    iss: str
    type: str
    scope: str
    jti: str
    exp: int
    iat: int


# ── CRUD ──────────────────────────────────────────────────────────────────────


class ServiceClientCreateRequest(BaseModel):
    service_id: str


class ServiceClientResponse(BaseModel):
    id: uuid.UUID
    service_id: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None

    model_config = {"from_attributes": True}


class ServiceClientCreateResponse(BaseModel):
    """Returned once at creation — includes the plaintext secret (never stored)."""

    id: uuid.UUID
    service_id: str
    service_secret: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class ServiceClientUpdateRequest(BaseModel):
    is_active: bool | None = None
