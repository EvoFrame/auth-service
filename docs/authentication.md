# Authentication

This document describes the core authentication flows built into `auth-service`:
registration, email verification, login, token refresh, logout, token introspection,
and password reset.

---

## Overview

`auth-service` issues two token types for human users:

- **Access token** — short-lived RS256-signed JWT (default: 15 min). Presented as a
  `Bearer` token in the `Authorization` header on every protected request.
- **Refresh token** — long-lived opaque composite token (default: 30 days). Used to
  obtain a new access token without re-entering credentials.

```
[Client]
  → POST /api/v1/users/login  { email, password, totp_code? }
  ← { access_token, refresh_token, expires_in }
```

---

## Registration flow

```
1. POST /api/v1/users/register    → creates user (is_verified=false)
2. auth-service publishes auth.user.registered event with a one-time verify_token
3. Email service (subscriber) sends the verification link to the user
4. POST /api/v1/users/verify-email { token }  → sets is_verified=true
```

The verification token is stored in Redis with a 24-hour TTL and is consumed on use
(single-use).

---

## Login flow

```
1. POST /api/v1/users/login
2. Credentials checked (Argon2)
3. Account checks: active, verified, not deleted
4. If mfa_enabled=true → TOTP code required in the same request
5. Issues access token (JWT) + refresh token (composite: <session_id>:<raw_token>)
```

The refresh token is stored as a hashed `RefreshSession` row in the database and a
Redis entry (TTL = `REFRESH_TOKEN_TTL`). The composite string encodes the session ID
and the raw secret so the server can look up and verify the session without a full
table scan.

---

## Token rotation

`POST /api/v1/users/refresh` performs **full token rotation**:

1. The incoming refresh session is revoked (both DB and Redis).
2. A new access token and a new refresh token are issued immediately.

Presenting an already-revoked refresh token returns `401`.

---

## Password reset flow

```
1. POST /api/v1/users/password-reset/request  { email }
   → stores a reset token in Redis (TTL: 1 h) and publishes auth.user.password_reset_requested
   → always returns 200 to prevent user enumeration

2. POST /api/v1/users/password-reset/confirm  { token, new_password }
   → validates token, rehashes password, revokes ALL active refresh sessions
   → publishes auth.user.password_reset
```

---

## Token introspection

`GET /api/v1/users/introspect` decodes and validates a user bearer token and returns
its claims. Used by internal services to verify a token without re-issuing it.

```json
{
  "sub": "<user_uuid>",
  "email": "user@example.com",
  "roles": ["admin"],
  "type": "user",
  "jti": "<uuid>",
  "iat": 1700000000,
  "exp": 1700000900
}
```

---

## API reference

These endpoints do **not** require an `X-Service-Token` (they are the public-facing auth
surface). All other endpoints in `auth-service` require a valid `X-Service-Token`.

### Registration & login

| Method | Path | Auth required | Description |
|---|---|---|---|
| `POST` | `/api/v1/users/register` | None | Register a new user |
| `POST` | `/api/v1/users/verify-email` | None | Verify email address with token |
| `POST` | `/api/v1/users/login` | None | Authenticate and issue tokens |
| `POST` | `/api/v1/users/refresh` | None | Rotate refresh token, issue new access token |
| `POST` | `/api/v1/users/logout` | None | Revoke the refresh session |
| `GET` | `/api/v1/users/introspect` | Bearer token | Decode and validate a user token |
| `GET` | `/api/v1/users/permissions/{user_id}` | None | Return user's roles and permissions |

### Password reset

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/users/password-reset/request` | Request a reset email |
| `POST` | `/api/v1/users/password-reset/confirm` | Apply new password with token |

**Login request body:**

```json
{
  "email": "user@example.com",
  "password": "s3cr3t",
  "totp_code": "123456"
}
```

`totp_code` is optional unless the account has MFA enabled.

**Token response:**

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<session_id>:<raw_token>",
  "expires_in": 900
}
```

---

## Data model

```
users
├── id               UUID   PK
├── email            TEXT   UNIQUE
├── password_hash    TEXT   Argon2id hash
├── is_active        BOOL   false = login blocked
├── is_verified      BOOL   false = login blocked until email verified
├── mfa_enabled      BOOL
├── totp_secret_enc  TEXT?  Fernet-encrypted TOTP secret
├── backup_email     TEXT?
├── backup_email_verified BOOL
├── created_at       TIMESTAMPTZ
├── updated_at       TIMESTAMPTZ
└── deleted_at       TIMESTAMPTZ?  soft-delete

refresh_sessions
├── id           UUID   PK  (the session_id in the composite token)
├── user_id      UUID   FK → users.id
├── token_hash   TEXT   Argon2id hash of the raw secret
├── expires_at   TIMESTAMPTZ
├── revoked_at   TIMESTAMPTZ?
├── ip           TEXT?
├── user_agent   TEXT?
└── created_at   TIMESTAMPTZ
```

---

## Domain events

| Stream | Published when |
|---|---|
| `auth.user.registered` | New user registered (includes `verify_token`) |
| `auth.user.password_reset_requested` | Reset token generated (includes `reset_token`) |
| `auth.user.password_reset` | Password successfully changed |

> `verify_token` and `reset_token` are included in events so that downstream services
> (e.g. a mail service) can build and deliver the link. They are never logged.

---

## Security notes

- Passwords are hashed with **Argon2id** (configurable time/memory/parallelism costs).
- The RS256 private key is held **only** by `auth-service`. All other services validate
  tokens using the public key.
- `POST /api/v1/users/password-reset/request` always returns a success response
  regardless of whether the email exists, to prevent user enumeration.
- All active refresh sessions are revoked when a password is reset, forcing re-login on
  all devices.
- Soft-deleted users (`deleted_at IS NOT NULL`) cannot log in.
