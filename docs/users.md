# Users

This document describes user management in `auth-service`: the self-service account API
(`/me`), admin user CRUD, and the backup email feature.

---

## Overview

User accounts can be managed through two surfaces:

- **Self-service** (`/api/v1/users/me`) — any authenticated user can read and update
  their own profile or delete their account.
- **Admin CRUD** (`/api/v1/users`) — privileged operations (list, get, update, delete any
  user) gated behind `users:read` / `users:write` RBAC permissions.

Both surfaces use **soft-delete**: deleting a user sets `deleted_at` rather than removing
the row. Deleted users cannot log in and are excluded from default list queries.

---

## Self-service endpoints

### Get current user

`GET /api/v1/users/me` — returns the authenticated user's profile.

```json
{
  "id": "<uuid>",
  "email": "user@example.com",
  "is_active": true,
  "is_verified": true,
  "mfa_enabled": false,
  "backup_email": null,
  "backup_email_verified": false,
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

### Update current user

`PATCH /api/v1/users/me` — update `email` and/or `backup_email`.

```json
{
  "email": "new@example.com",
  "backup_email": "backup@example.com"
}
```

Both fields are optional. Constraints:

- The new `email` must not be taken by another user (409 `EMAIL_TAKEN`).
- The `backup_email` must not be taken by another user (409 `BACKUP_EMAIL_TAKEN`).
- `backup_email` must differ from `email` (409 `BACKUP_EMAIL_SAME_AS_PRIMARY`).
- Changing `backup_email` resets `backup_email_verified` to `false`.

### Delete current user

`DELETE /api/v1/users/me` — soft-deletes the account and **revokes all active refresh
sessions**, immediately invalidating all devices.

---

## Backup email

A user can register a secondary email address (`backup_email`) on their account. It is
stored separately from the primary email and has its own `backup_email_verified` flag.

Typical use: recovery path, account notifications, or as a fallback login identifier
(implementation of backup-email-based login is left to downstream consumers via domain
events).

The field is managed through `PATCH /api/v1/users/me` (self-service) or
`PATCH /api/v1/users/{user_id}` (admin). `backup_email` is globally unique across all
users — two accounts cannot share the same backup email.

---

## Admin user CRUD

All admin endpoints require a valid `X-Service-Token` and the appropriate RBAC permission.

| Method   | Path                      | Permission    | Description            |
| -------- | ------------------------- | ------------- | ---------------------- |
| `GET`    | `/api/v1/users`           | `users:read`  | List users (paginated) |
| `GET`    | `/api/v1/users/{user_id}` | `users:read`  | Get a single user      |
| `PATCH`  | `/api/v1/users/{user_id}` | `users:write` | Update user fields     |
| `DELETE` | `/api/v1/users/{user_id}` | `users:write` | Soft-delete user       |

### List query parameters

| Parameter         | Default | Description                |
| ----------------- | ------- | -------------------------- |
| `page`            | `1`     | Page number (1-based)      |
| `page_size`       | `20`    | Items per page (max 100)   |
| `include_deleted` | `false` | Include soft-deleted users |

### Admin update fields

| Field                   | Type      | Description                                      |
| ----------------------- | --------- | ------------------------------------------------ |
| `email`                 | `string?` | Change the user's primary email                  |
| `backup_email`          | `string?` | Set or change the backup email                   |
| `backup_email_verified` | `bool?`   | Override the backup email verified flag          |
| `is_active`             | `bool?`   | Enable or disable the account                    |
| `is_verified`           | `bool?`   | Mark email as verified (e.g. after manual check) |

Admins can set `backup_email_verified` directly (e.g. after sending a verification flow
through a separate channel), whereas self-service resets it to `false` whenever the
backup email address changes.

---

## Data model

```
users
├── id                    UUID   PK
├── email                 TEXT   UNIQUE
├── password_hash         TEXT
├── is_active             BOOL   false = login blocked
├── is_verified           BOOL   false = login blocked
├── mfa_enabled           BOOL
├── totp_secret_enc       TEXT?  Fernet-encrypted TOTP secret
├── backup_email          TEXT?  UNIQUE
├── backup_email_verified BOOL
├── created_at            TIMESTAMPTZ
├── updated_at            TIMESTAMPTZ
└── deleted_at            TIMESTAMPTZ?  NULL = active
```

---

## Domain events

| Stream              | Published when                            |
| ------------------- | ----------------------------------------- |
| `auth.user.deleted` | User account soft-deleted (self or admin) |

---

## Security notes

- Soft-deleted users cannot log in. Their records are retained for audit purposes.
- Deleting an account immediately revokes all refresh sessions (forces logout on all
  devices). Active access tokens remain valid until they expire naturally (default 15 min).
- Admin updates to `is_active = false` block login on the next token check, but existing
  access tokens remain valid until expiry. Use ABAC deny policies if immediate revocation
  is required.
