# Copilot Instructions — auth-service

## Project overview

`auth-service` is the **central authentication and authorization service** for the EvoFrame
platform. It is a Python/FastAPI application that handles:

- User registration, login, password management, MFA (TOTP), and OAuth2 (Google, GitHub)
- JWT issuance (access + refresh tokens, RS256)
- Role-Based Access Control (RBAC) — coarse-grained, enforced inside auth-service
- Attribute-Based Access Control (ABAC) — fine-grained, pull-model evaluated by internal services
- Machine-to-machine service tokens (M2M / service-client tokens)
- Background tasks (expired token cleanup via APScheduler)
- Event publishing to Redis Streams

## Tech stack

| Concern | Choice |
|---|---|
| Framework | FastAPI + Uvicorn/Gunicorn |
| ORM / models | SQLModel (SQLAlchemy async) |
| Database | PostgreSQL (asyncpg driver) |
| Cache / events | Redis (redis-py async) |
| Migrations | Alembic |
| JWT | PyJWT (RS256 only) |
| Password hashing | Argon2 (argon2-cffi) |
| TOTP | pyotp + Fernet encryption for secrets |
| OAuth2 clients | Authlib |
| Settings | pydantic-settings (`.env` + `.env.local`) |
| Logging | structlog (structured JSON) |
| Metrics | prometheus-fastapi-instrumentator (`/metrics`) |
| Task runner | mise (tasks) |
| Package manager | uv |
| Dev environment | mise |
| Linter/formatter | Ruff |
| Tests | pytest-asyncio + testcontainers (Postgres + Redis) |

## Repository layout

```
resources/
  server.py               # App factory — create_app(), lifespan
  src/
    config/
      settings.py         # Pydantic-settings Settings singleton
      logging.py          # structlog configuration
    controllers/          # Business logic (no HTTP concerns)
      users.py            # Register, login, password reset, MFA, backup email
      oauth.py            # Google/GitHub OAuth2 flows
      mfa.py              # TOTP setup, verify, disable
      abac.py             # ABAC evaluation + user attributes + policy CRUD
      rbac_mgmt.py        # Role/permission CRUD, assignment
      service_clients.py  # Service-client CRUD + token issuance
    routers/              # FastAPI route handlers (thin; delegate to controllers)
      users.py
      rbac.py
      abac.py
      service_clients.py
    schemas/              # Pydantic request/response schemas
    models/               # SQLModel table models
      user.py             # User
      session.py          # RefreshSession
      rbac.py             # Role, Permission, RolePermission, UserRole
      abac.py             # UserAttribute, Policy, PolicyCondition
      service_client.py   # ServiceClient
    libs/
      auth_deps.py        # get_current_user(), require_permission() FastAPI deps
      abac_engine.py      # Pure-Python ABAC evaluation engine (no I/O)
      errors.py           # AppError exception + register_exception_handlers()
      pagination.py       # Shared pagination helpers
      health.py           # /health router
      s2s_client.py       # HTTP client for outbound service-to-service calls
      service_token_cache.py  # Redis-backed service token cache
    middlewares/
      service_auth.py     # Validates X-Service-Token on every non-exempt route
      logging.py          # Structured request/response logging
      request_id.py       # Injects X-Request-ID into request state
    db/
      session.py          # get_session() async dependency
      base.py             # SQLAlchemy engine setup
    redis/
      client.py           # get_redis() async dependency
    events/
      publisher.py        # EventPublisher — publishes to Redis Streams
      consumers/          # Redis Stream consumers (started at lifespan)
    tasks/
      token_cleanup.py    # APScheduler job: purge expired refresh sessions
  tests/
    conftest.py           # Session-scoped testcontainers (Postgres + Redis), async client
    integration/          # End-to-end HTTP tests via ASGI client
    unit/                 # Pure logic tests (ABAC engine, MFA, RBAC)
resources/migrations/     # Alembic migration scripts
```

## Key architecture rules

1. **Routers are thin** — all logic lives in `controllers/`. Routers validate input,
   call the controller, and return the response.

2. **AppError everywhere** — raise `AppError(code, message, status_code)` for all
   expected error conditions. Never raise `HTTPException` directly.

3. **No I/O in the ABAC engine** — `abac_engine.py` is a pure function. The controller
   loads data and builds the context before calling it.

4. **Service auth is enforced by middleware** — all routes except
   `/health`, `/docs`, `/openapi`, `/metrics`, `/redoc`, and
   `/api/v1/service-clients/token` require a valid `X-Service-Token: Bearer <jwt>` header.
   In tests this is bypassed via `SKIP_SERVICE_AUTH=true`.

5. **RS256 only** — auth-service is the ONLY service that holds the private key.
   Other services validate tokens with the public key only.

6. **Audit columns last** — all SQLModel table classes end with
   `created_at`, `updated_at`, and optionally `deleted_at`.

7. **Soft deletes on users** — `users.deleted_at` is set instead of hard-deleting rows.

## Auth flow summary

```
POST /api/v1/users/login
  → issues access_token (RS256, TTL 15 min, type=user) + refresh_token (hashed, DB row)

POST /api/v1/users/refresh
  → validates refresh token hash, issues new access_token

POST /api/v1/service-clients/token
  → issues service_token (RS256, TTL 5 min, type=service, scope=internal)
```

JWT claims for user tokens: `{ sub: user_id, type: "user", email, roles, permissions }`
JWT claims for service tokens: `{ sub: service_id, type: "service", scope: "internal" }`

## RBAC vs ABAC

| | RBAC | ABAC |
|---|---|---|
| Granularity | Coarse (permission names) | Fine (attribute conditions) |
| Enforced by | auth-service (`require_permission`) | Calling service acting on `/abac/evaluate` verdict |
| Default | deny if missing permission | deny if no policy fires |

ABAC evaluation endpoint: `POST /api/v1/abac/evaluate`

See `docs/abac.md` for full ABAC documentation.

## Common patterns

### Add a new endpoint

1. Add schema(s) in `schemas/`
2. Add business logic in the relevant `controllers/` module
3. Add route in the relevant `routers/` module using
   `Depends(require_permission("perm:name"))` for auth

### Raise an error

```python
from src.libs.errors import AppError

raise AppError("SOME_CODE", "Human-readable message.", status_code=404)
```

### Access the database

```python
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from src.db.session import get_session

async def my_endpoint(session: AsyncSession = Depends(get_session)):
    ...
```

### Publish an event

```python
from src.events.publisher import EventPublisher

publisher = EventPublisher(request.app.state.redis)
await publisher.publish("auth.some.event", {"key": "value"})
```

## Running the project

```bash
# One-time setup
mise run setup                  # init env files + generate RSA keys
mise run setup:init-env         # copy *.example env files only
mise run setup:rotate-keys      # (re)generate RSA key pair → injected into .env

# Daily dev
mise run dev                    # start infra (db + redis) + migrate + dev server

# Stack management
mise run stack:up               # start infra only (db + redis)
mise run stack:up --services    # start infra + app container
mise run stack:up --ui          # + pgAdmin + RedisInsight
mise run stack:up --monitoring  # + Prometheus + Grafana + Loki
mise run stack:down             # stop and remove all containers

# Testing
mise run test:run               # full suite with coverage
mise run test:unit              # unit tests only
mise run test:integration       # integration tests only

# Database
mise run db:migrate             # apply pending Alembic migrations
mise run db:new                 # generate a new migration (pass name as arg)
mise run db:rollback            # rollback one step
mise run db:seed                # seed default roles and permissions

# Linting
mise run lint:check             # ruff check (report only)
mise run lint:fix               # auto-fix lint issues
mise run lint:format            # fix imports + reformat

# Dependencies
mise run deps:sync              # sync from uv.lock
mise run deps:add               # add a runtime dep
mise run deps:add-dev           # add a dev dep
mise run deps:update            # upgrade all deps

# Docker helpers
mise run docker:logs [service]  # follow logs (all containers or one)
mise run docker:ps              # list container status
mise run docker:build           # rebuild app image
mise run docker:clean           # ⚠ remove all containers + volumes
```

## Environment variables (required)

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | asyncpg PostgreSQL URL |
| `REDIS_URL` | Redis URL |
| `RS256_PRIVATE_KEY` | PEM private key (single-line with `\n` escapes OK) |
| `RS256_PUBLIC_KEY` | PEM public key |
| `SERVICE_SECRET` | Shared secret for bootstrapping service tokens |
| `TOTP_ENCRYPTION_KEY` | Fernet key (base64, 32-byte) for TOTP secret encryption |

Optional: `GOOGLE_CLIENT_ID/SECRET`, `GITHUB_CLIENT_ID/SECRET`, `DEBUG`, `SKIP_SERVICE_AUTH`

## Testing conventions

- All tests use a **session-scoped** ASGI `AsyncClient` (no real HTTP server).
- Testcontainers spin up real Postgres + Redis containers — no mocking of DB/Redis.
- Containers are started **before any `src.*` import** in `conftest.py` so
  `pydantic-settings` picks up the correct env vars.
- `SKIP_SERVICE_AUTH=true` bypasses `X-Service-Token` validation in tests.
- Test files mirror the source structure: `tests/integration/test_<feature>.py`.
- Fixtures are defined in `tests/conftest.py` (session scope by default).

## Code style

- Formatter: Ruff (`line-length = 120`, `quote-style = "double"`)
- Linting rules: `E`, `F`, `I` (isort), `UP` (pyupgrade)
- Python ≥ 3.13; use modern typing (`str | None`, `list[str]`, etc.)
- Docstrings: Google-style, on all public functions and classes
