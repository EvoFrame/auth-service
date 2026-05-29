"""Service clients controller — M2M token flows + CRUD."""

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import structlog
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.events.publisher import EventPublisher
from src.libs.errors import AppError
from src.libs.pagination import PagedResponse, paginate
from src.models.service_client import ServiceClient
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

logger = structlog.get_logger()

_ph = PasswordHasher(
    time_cost=settings.ARGON2_TIME_COST,
    memory_cost=settings.ARGON2_MEMORY_COST,
    parallelism=settings.ARGON2_PARALLELISM,
)


# ── Token flows ───────────────────────────────────────────────────────────────


async def issue_service_token(
    body: ServiceTokenRequest,
    session: AsyncSession,
    publisher: EventPublisher,
) -> ServiceTokenResponse:
    client = (
        await session.execute(
            select(ServiceClient).where(
                ServiceClient.service_id == body.service_id,
                ServiceClient.is_active == True,  # noqa: E712
                ServiceClient.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()

    if not client:
        raise AppError("INVALID_CREDENTIALS", "Invalid service credentials.", status_code=401)

    try:
        _ph.verify(client.secret_hash, body.service_secret)
    except VerifyMismatchError:
        raise AppError("INVALID_CREDENTIALS", "Invalid service credentials.", status_code=401)

    jti = str(uuid.uuid4())
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=settings.SERVICE_TOKEN_TTL)

    payload = {
        "jti": jti,
        "sub": body.service_id,
        "iss": settings.SERVICE_ID,
        "type": "service",
        "scope": "internal",
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    token = jwt.encode(payload, settings.RS256_PRIVATE_KEY, algorithm="RS256")

    await publisher.publish(
        "auth.service.token_issued",
        {
            "issuer_service": settings.SERVICE_ID,
            "issued_to_service": body.service_id,
            "token_jti": jti,
            "expires_at": expires_at.isoformat(),
        },
        issuer_service=settings.SERVICE_ID,
        issued_to_service=body.service_id,
    )
    logger.info("service_token_issued", issued_to=body.service_id, jti=jti)

    return ServiceTokenResponse(access_token=token, expires_in=settings.SERVICE_TOKEN_TTL)


async def introspect_service_token(body: ServiceIntrospectRequest) -> ServiceIntrospectResponse:
    try:
        payload = jwt.decode(
            body.token,
            settings.RS256_PUBLIC_KEY,
            algorithms=["RS256"],
        )
    except jwt.ExpiredSignatureError:
        raise AppError("TOKEN_EXPIRED", "Service token has expired.", status_code=401)
    except jwt.InvalidTokenError:
        raise AppError("INVALID_TOKEN", "Invalid service token.", status_code=401)

    if payload.get("type") != "service" or payload.get("scope") != "internal":
        raise AppError("INVALID_TOKEN", "Not a valid service token.", status_code=401)

    return ServiceIntrospectResponse(
        sub=payload["sub"],
        iss=payload["iss"],
        type=payload["type"],
        scope=payload["scope"],
        jti=payload["jti"],
        exp=payload["exp"],
        iat=payload["iat"],
    )


# ── CRUD ──────────────────────────────────────────────────────────────────────


async def create_service_client(
    body: ServiceClientCreateRequest,
    session: AsyncSession,
    publisher: EventPublisher,
) -> ServiceClientCreateResponse:
    existing = (
        await session.execute(select(ServiceClient).where(ServiceClient.service_id == body.service_id))
    ).scalar_one_or_none()
    if existing:
        raise AppError("SERVICE_ID_TAKEN", "Service ID is already registered.", status_code=409)

    secret = secrets.token_urlsafe(48)
    client = ServiceClient(service_id=body.service_id, secret_hash=_ph.hash(secret))
    session.add(client)
    await session.commit()
    await session.refresh(client)

    await publisher.publish("auth.service.client_created", {"service_id": body.service_id})
    logger.info("service_client_created", service_id=body.service_id)

    return ServiceClientCreateResponse(
        id=client.id,
        service_id=client.service_id,
        service_secret=secret,
        is_active=client.is_active,
        created_at=client.created_at,
    )


async def list_service_clients(
    session: AsyncSession,
    page: int,
    page_size: int,
    include_deleted: bool = False,
) -> PagedResponse[ServiceClientResponse]:
    base_q = select(ServiceClient)
    count_q = select(func.count()).select_from(ServiceClient)
    if not include_deleted:
        base_q = base_q.where(ServiceClient.deleted_at.is_(None))
        count_q = count_q.where(ServiceClient.deleted_at.is_(None))

    total = (await session.execute(count_q)).scalar_one()
    clients = (
        await session.execute(base_q.offset((page - 1) * page_size).limit(page_size))
    ).scalars().all()

    return paginate([ServiceClientResponse.model_validate(c) for c in clients], total, page, page_size)


async def get_service_client(service_id: str, session: AsyncSession) -> ServiceClientResponse:
    client = (
        await session.execute(select(ServiceClient).where(ServiceClient.service_id == service_id))
    ).scalar_one_or_none()
    if not client:
        raise AppError("SERVICE_CLIENT_NOT_FOUND", "Service client not found.", status_code=404)
    return ServiceClientResponse.model_validate(client)


async def update_service_client(
    service_id: str,
    body: ServiceClientUpdateRequest,
    session: AsyncSession,
) -> ServiceClientResponse:
    client = (
        await session.execute(select(ServiceClient).where(ServiceClient.service_id == service_id))
    ).scalar_one_or_none()
    if not client:
        raise AppError("SERVICE_CLIENT_NOT_FOUND", "Service client not found.", status_code=404)
    if client.deleted_at is not None:
        raise AppError("SERVICE_CLIENT_DELETED", "Cannot update a deleted service client.", status_code=409)

    if body.is_active is not None:
        client.is_active = body.is_active

    await session.commit()
    await session.refresh(client)
    return ServiceClientResponse.model_validate(client)


async def delete_service_client(
    service_id: str,
    session: AsyncSession,
    publisher: EventPublisher,
) -> dict:
    client = (
        await session.execute(select(ServiceClient).where(ServiceClient.service_id == service_id))
    ).scalar_one_or_none()

    if not client:
        raise AppError("SERVICE_CLIENT_NOT_FOUND", "Service client not found.", status_code=404)

    if client.deleted_at is not None:
        raise AppError("SERVICE_CLIENT_ALREADY_DELETED", "Service client is already deleted.", status_code=409)

    client.deleted_at = datetime.now(UTC)
    await session.commit()

    await publisher.publish("auth.service.client_deleted", {"service_id": service_id})
    logger.info("service_client_deleted", service_id=service_id)
    return {"message": "Service client deleted successfully."}
