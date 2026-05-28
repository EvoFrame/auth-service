"""Test fixtures: containerised Postgres + Redis, app override, async client.

Containers are started at conftest import time so that ``os.environ`` is
populated *before* any ``src.*`` module is imported — pydantic-settings reads
env vars when Settings() is first instantiated.
"""

import atexit
import os
from collections.abc import AsyncGenerator

import pytest_asyncio
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool
from sqlmodel import SQLModel
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer


# ── Generate a fresh RSA key-pair for each test run ──────────────────────────
def _generate_rsa_keys() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    pub = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return priv, pub


_TEST_PRIVATE_KEY, _TEST_PUBLIC_KEY = _generate_rsa_keys()
_TEST_FERNET_KEY = Fernet.generate_key().decode()

# ── Start containers eagerly — BEFORE any src.* import ───────────────────────
_pg_ctr = PostgresContainer("postgres:16-alpine")
_redis_ctr = RedisContainer("redis:7-alpine")
_pg_ctr.start()
_redis_ctr.start()
atexit.register(_pg_ctr.stop)
atexit.register(_redis_ctr.stop)

os.environ.update(
    {
        "DATABASE_URL": _pg_ctr.get_connection_url().replace("psycopg2", "asyncpg"),
        "REDIS_URL": (
            f"redis://{_redis_ctr.get_container_host_ip()}:{_redis_ctr.get_exposed_port(6379)}/0"
        ),
        "RS256_PRIVATE_KEY": _TEST_PRIVATE_KEY,
        "RS256_PUBLIC_KEY": _TEST_PUBLIC_KEY,
        "SERVICE_SECRET": "test-service-secret",
        "TOTP_ENCRYPTION_KEY": _TEST_FERNET_KEY,
        "APP_ENV": "test",
        "DEBUG": "true",
    }
)

# Safe to import src modules now
from src.config.settings import settings  # noqa: E402
from src.db.session import get_session  # noqa: E402
from src.events.publisher import EventPublisher  # noqa: E402
from src.redis.client import get_redis  # noqa: E402


@pytest_asyncio.fixture(scope="session")
async def db_engine():
    # NullPool: each AsyncSession creates its own connection on the calling loop,
    # avoiding asyncpg "attached to a different loop" errors.
    engine = create_async_engine(settings.DATABASE_URL, echo=False, poolclass=NullPool)
    async with engine.begin() as conn:
        import src.models  # noqa: F401

        await conn.run_sync(SQLModel.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="session")
async def redis_client():
    import redis.asyncio as aioredis

    client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture(scope="session")
async def client(db_engine, redis_client) -> AsyncGenerator[AsyncClient]:
    """ASGI test client with overridden DB and Redis deps."""
    from server import create_app

    app = create_app()

    async def _override_session():
        async with AsyncSession(db_engine, expire_on_commit=False) as session:
            yield session

    async def _override_redis():
        return redis_client

    app.dependency_overrides[get_session] = _override_session
    app.dependency_overrides[get_redis] = _override_redis
    app.state.redis = redis_client
    app.state.publisher = EventPublisher(redis_client)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac
