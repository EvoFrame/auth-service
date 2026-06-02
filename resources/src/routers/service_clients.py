"""Service clients router — M2M token flows and admin CRUD."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.controllers import service_clients as sc_ctrl
from src.db.session import get_session
from src.events.publisher import EventPublisher
from src.libs.auth_deps import require_permission
from src.libs.pagination import PagedResponse
from src.models.user import User
from src.redis.client import get_redis
from src.schemas.service_clients import (
    ServiceClientCreateRequest,
    ServiceClientCreateResponse,
    ServiceClientResponse,
    ServiceClientUpdateRequest,
    ServiceIntrospectRequest,
    ServiceIntrospectResponse,
    ServiceTokenRequest,
    ServiceTokenResponse,
)


async def _get_publisher(redis=Depends(get_redis)) -> EventPublisher:
    return EventPublisher(redis)


# ── Token flows (public — authenticated by service secret / JWT) ──────────────

_token_router = APIRouter(prefix="/service-clients", tags=["Service Tokens"])


@_token_router.post("/token", response_model=ServiceTokenResponse)
async def service_token(
    body: ServiceTokenRequest,
    session: AsyncSession = Depends(get_session),
    publisher: EventPublisher = Depends(_get_publisher),
):
    return await sc_ctrl.issue_service_token(body, session, publisher)


@_token_router.post("/introspect", response_model=ServiceIntrospectResponse)
async def service_introspect(body: ServiceIntrospectRequest):
    return await sc_ctrl.introspect_service_token(body)


# ── Admin CRUD ────────────────────────────────────────────────────────────────

_admin_router = APIRouter(prefix="/service-clients", tags=["Admin — Service Clients"])


@_admin_router.post("", response_model=ServiceClientCreateResponse, status_code=201)
async def create_service_client(
    body: ServiceClientCreateRequest,
    session: AsyncSession = Depends(get_session),
    publisher: EventPublisher = Depends(_get_publisher),
    _: User = Depends(require_permission("service_clients:write")),
):
    return await sc_ctrl.create_service_client(body, session, publisher)


@_admin_router.get("", response_model=PagedResponse[ServiceClientResponse])
async def list_service_clients(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    include_deleted: bool = Query(False),
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_permission("service_clients:read")),
):
    return await sc_ctrl.list_service_clients(session, page, page_size, include_deleted)


@_admin_router.get("/{service_id}", response_model=ServiceClientResponse)
async def get_service_client(
    service_id: str,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_permission("service_clients:read")),
):
    return await sc_ctrl.get_service_client(service_id, session)


@_admin_router.patch("/{service_id}", response_model=ServiceClientResponse)
async def update_service_client(
    service_id: str,
    body: ServiceClientUpdateRequest,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_permission("service_clients:write")),
):
    return await sc_ctrl.update_service_client(service_id, body, session)


@_admin_router.delete("/{service_id}", status_code=200)
async def delete_service_client(
    service_id: str,
    session: AsyncSession = Depends(get_session),
    publisher: EventPublisher = Depends(_get_publisher),
    _: User = Depends(require_permission("service_clients:write")),
):
    return await sc_ctrl.delete_service_client(service_id, session, publisher)


# ── Main service-clients router ───────────────────────────────────────────────

router = APIRouter()
router.include_router(_token_router)
router.include_router(_admin_router)
