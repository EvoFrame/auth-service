# Service Clients — Machine-to-Machine Authentication

This document describes the M2M (machine-to-machine) authentication system built into
`auth-service`, covering service client registration, token issuance, and introspection.

---

## Overview

Internal services that need to call other internal services (or `auth-service` itself)
must identify themselves using a **service token** — a short-lived RS256-signed JWT
distinct from user access tokens.

```
[Internal service]
  → POST /api/v1/service-clients/token
    { service_id, service_secret }
  ← { access_token, expires_in }

[Internal service calls another service]
  → GET /api/v1/some/resource
    X-Service-Token: Bearer <service_token>
```

The token is validated by `ServiceAuthMiddleware` on every non-exempt route of
`auth-service`. Other internal services validate it the same way using the shared
RS256 public key.

---

## Service client registration

A service client is a record in the database representing a specific internal service.
It holds:

- A unique **`service_id`** string (e.g. `"worker-service"`, `"api-gateway"`).
- A hashed **`service_secret`** (Argon2id). The plain-text secret is returned only once
  at creation and must be stored securely by the caller.

Registration is an admin operation requiring the `service_clients:write` permission.

---

## Token flow

```
1. POST /api/v1/service-clients/token
     { "service_id": "worker-service", "service_secret": "<plain secret>" }

2. auth-service looks up the ServiceClient by service_id (active, not deleted)
3. Verifies secret against the stored Argon2id hash
4. Issues a JWT signed with RS256:
     {
       "jti":   "<uuid>",
       "sub":   "worker-service",       ← the calling service's identity
       "iss":   "auth-service",
       "type":  "service",
       "scope": "internal",
       "iat":   <timestamp>,
       "exp":   <timestamp + SERVICE_TOKEN_TTL>
     }
5. Publishes auth.service.token_issued event
```

Default TTL: **5 minutes** (`SERVICE_TOKEN_TTL`). Services should cache and reuse the
token until near expiry rather than re-authenticating on every request.

---

## Token validation (ServiceAuthMiddleware)

Every route in `auth-service` (except the token endpoint, health, docs, and metrics)
requires a valid `X-Service-Token: Bearer <token>` header.

The middleware:

1. Decodes and verifies the JWT signature against the RS256 public key.
2. Checks `type == "service"` and `scope == "internal"`.
3. Injects `request.state.caller_service = payload["sub"]` for downstream use.

Failed validation returns `403 Forbidden` and publishes an `auth.access.denied` event.

**Exempt paths** (no service token required):

- `/health`, `/docs`, `/openapi`, `/redoc`, `/metrics`
- `POST /api/v1/service-clients/token` (bootstrap — a service needs to authenticate
  before it has a token)

---

## Token introspection

`POST /api/v1/service-clients/introspect` decodes and validates a service token and
returns its claims. Useful when a service wants to inspect a token presented to it.

**Request:**

```json
{ "token": "<service_jwt>" }
```

**Response:**

```json
{
  "sub":   "worker-service",
  "iss":   "auth-service",
  "type":  "service",
  "scope": "internal",
  "jti":   "<uuid>",
  "iat":   1700000000,
  "exp":   1700000300
}
```

---

## API reference

### Token flows (public — no prior service token needed)

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/service-clients/token` | Authenticate and issue a service token |
| `POST` | `/api/v1/service-clients/introspect` | Decode and validate a service token |

### Admin CRUD (requires `X-Service-Token` + permission)

| Method | Path | Permission | Description |
|---|---|---|---|
| `POST` | `/api/v1/service-clients` | `service_clients:write` | Register a new service client |
| `GET` | `/api/v1/service-clients` | `service_clients:read` | List service clients (paginated) |
| `GET` | `/api/v1/service-clients/{service_id}` | `service_clients:read` | Get a single service client |
| `PATCH` | `/api/v1/service-clients/{service_id}` | `service_clients:write` | Update (e.g. enable/disable) |
| `DELETE` | `/api/v1/service-clients/{service_id}` | `service_clients:write` | Soft-delete a service client |

**Create response** (secret shown once):

```json
{
  "id": "<uuid>",
  "service_id": "worker-service",
  "service_secret": "<plain-text secret — store this securely>",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00Z"
}
```

**List query parameters:**

| Parameter | Default | Description |
|---|---|---|
| `page` | `1` | Page number (1-based) |
| `page_size` | `20` | Items per page (max 100) |
| `include_deleted` | `false` | Include soft-deleted clients |

---

## Data model

```
service_clients
├── id           UUID   PK
├── service_id   TEXT   UNIQUE  — the service's name/identifier
├── secret_hash  TEXT   Argon2id hash of the plain-text secret
├── is_active    BOOL   false = token issuance blocked
├── created_at   TIMESTAMPTZ
├── updated_at   TIMESTAMPTZ
└── deleted_at   TIMESTAMPTZ?  soft-delete
```

---

## Domain events

| Stream | Published when |
|---|---|
| `auth.service.token_issued` | A service token was successfully issued |
| `auth.service.client_created` | A new service client was registered |
| `auth.service.client_deleted` | A service client was soft-deleted |
| `auth.access.denied` | A request was rejected by `ServiceAuthMiddleware` |

---

## Security notes

- The `service_secret` is returned **only once** at creation. If lost, the service client
  must be deleted and re-created.
- Secrets are hashed with **Argon2id** before storage.
- Service tokens are **short-lived** (5 min by default). Compromised tokens expire quickly.
- Disabling a client (`is_active = false`) immediately blocks new token issuance; existing
  valid tokens remain valid until they expire naturally (no revocation list).
- In development, `ServiceAuthMiddleware` can be bypassed by setting `DEBUG=true` and
  `SKIP_SERVICE_AUTH=true`. This must never be used in production.
- The RS256 private key is held only by `auth-service`. All other services only need the
  public key to validate tokens.
