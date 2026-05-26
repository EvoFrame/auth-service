"""Service token controller — M2M token issuance and introspection."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import structlog
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.events.publisher import EventPublisher
from src.libs.errors import AppError
from src.models.service_client import ServiceClient
from src.schemas.service import (
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


async def issue_service_token(
    body: ServiceTokenRequest,
    session: AsyncSession,
    publisher: EventPublisher,
) -> ServiceTokenResponse:
    client = (await session.execute(
        select(ServiceClient).where(
            ServiceClient.service_id == body.service_id,
            ServiceClient.is_active == True,  # noqa: E712
        )
    )).scalar_one_or_none()

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
