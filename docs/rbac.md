# RBAC — Role-Based Access Control

This document describes the RBAC system built into `auth-service`, how roles and
permissions are managed, and how they are enforced on API endpoints.

---

## Overview

RBAC provides **coarse-grained** authorization: a user is granted one or more roles, each
of which bundles a set of named permissions. When a protected endpoint is called, the
service checks that the bearer token's owner holds all required permissions before
proceeding.

```
User → UserRole → Role → RolePermission → Permission
```

Roles and permissions are stored in the database and managed through the admin API.
Permission names are free-form strings (e.g. `users:read`, `abac:write`). There are no
built-in roles — all roles are created by administrators.

---

## Enforcement

Permission checks are performed inside `auth-service` itself via the `require_permission`
FastAPI dependency. Any endpoint decorated with this dependency will:

1. Validate the `Authorization: Bearer <token>` header.
2. Load the user from the database; reject disabled or deleted accounts.
3. Query all permissions derived from the user's roles.
4. Return `403 FORBIDDEN` if any required permission is missing.

```python
@router.get("/users", dependencies=[Depends(require_permission("users:read"))])
```

---

## Core concepts

### Roles

A named group of permissions. Role names must be unique. A role can have zero or more
permissions; an empty role grants nothing.

### Permissions

Atomic capability strings. Permission names must be unique. The naming convention used
throughout `auth-service` is `resource:action` (e.g. `roles:write`, `abac:evaluate`),
but any string is accepted.

### Assignments

- **Role → Permission**: `POST /api/v1/rbac/roles/{role_id}/permissions/{permission_id}` —
  idempotent; assigning an already-assigned permission is a no-op.
- **User → Role**: `POST /api/v1/rbac/users/{user_id}/roles/{role_id}` — idempotent.

Deleting a role automatically removes all its permission assignments and all user
assignments to that role. Deleting a permission removes all its role assignments.

---

## Built-in permission names used by `auth-service`

| Permission | Used by |
|---|---|
| `users:read` | List/get users (admin) |
| `users:write` | Update/delete users (admin) |
| `roles:read` | List/get roles and permissions |
| `roles:write` | Create/update/delete roles and permissions, manage assignments |
| `abac:read` | Read ABAC policies, conditions, user attributes |
| `abac:write` | Create/update/delete ABAC policies, conditions, user attributes |
| `abac:evaluate` | Call `POST /abac/evaluate` |
| `service_clients:read` | List/get service clients |
| `service_clients:write` | Create/update/delete service clients |

---

## API reference

All endpoints require a valid `X-Service-Token` and one of the permissions below.

### Roles

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/rbac/roles` | `roles:read` | List all roles (paginated) |
| `POST` | `/api/v1/rbac/roles` | `roles:write` | Create a new role |
| `GET` | `/api/v1/rbac/roles/{role_id}` | `roles:read` | Get a role with its permissions |
| `PATCH` | `/api/v1/rbac/roles/{role_id}` | `roles:write` | Update role name / description |
| `DELETE` | `/api/v1/rbac/roles/{role_id}` | `roles:write` | Delete a role |

### Permissions

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/rbac/permissions` | `roles:read` | List all permissions (paginated) |
| `POST` | `/api/v1/rbac/permissions` | `roles:write` | Create a new permission |
| `DELETE` | `/api/v1/rbac/permissions/{permission_id}` | `roles:write` | Delete a permission |

### Role ↔ Permission assignments

| Method | Path | Permission | Description |
|---|---|---|---|
| `POST` | `/api/v1/rbac/roles/{role_id}/permissions/{permission_id}` | `roles:write` | Assign permission to role |
| `DELETE` | `/api/v1/rbac/roles/{role_id}/permissions/{permission_id}` | `roles:write` | Remove permission from role |

### User ↔ Role assignments

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/rbac/users/{user_id}/roles` | `roles:read` | Get user's roles and permissions |
| `POST` | `/api/v1/rbac/users/{user_id}/roles/{role_id}` | `roles:write` | Assign role to user |
| `DELETE` | `/api/v1/rbac/users/{user_id}/roles/{role_id}` | `roles:write` | Remove role from user |

---

## Data model

```
roles
├── id           UUID   PK
├── name         TEXT   UNIQUE
├── description  TEXT?
├── created_at   TIMESTAMPTZ
└── updated_at   TIMESTAMPTZ

permissions
├── id           UUID   PK
├── name         TEXT   UNIQUE
├── description  TEXT?
├── created_at   TIMESTAMPTZ
└── updated_at   TIMESTAMPTZ

role_permissions
├── role_id        UUID   FK → roles.id       (composite PK)
└── permission_id  UUID   FK → permissions.id (composite PK)

user_roles
├── user_id      UUID   FK → users.id  (composite PK)
├── role_id      UUID   FK → roles.id  (composite PK)
└── assigned_at  TIMESTAMPTZ
```

---

## RBAC in access tokens

When a user logs in, their current role names are embedded in the JWT payload:

```json
{
  "sub": "<user_uuid>",
  "roles": ["admin", "editor"],
  ...
}
```

The token is **not** updated when roles change mid-session. Role changes take effect on
the next login or token refresh. Use `GET /api/v1/users/permissions/{user_id}` to query
the current live permissions for a user.

---

## Coexistence with ABAC

RBAC and ABAC are independent systems:

- **RBAC** controls access to `auth-service`'s own endpoints (admin APIs, ABAC management,
  etc.) via `require_permission`.
- **ABAC** is used by other services to make fine-grained authorization decisions about
  their own resources.

The user's roles and permissions are automatically included in the ABAC `subject` bag
(as `roles` and `permissions` JSON arrays), so ABAC policies can reference RBAC data.

---

## Example: bootstrap an admin user

```bash
# 1. Create the admin role
POST /api/v1/rbac/roles
{ "name": "admin", "description": "Full access" }

# 2. Create required permissions
POST /api/v1/rbac/permissions  { "name": "users:read" }
POST /api/v1/rbac/permissions  { "name": "users:write" }
POST /api/v1/rbac/permissions  { "name": "roles:read" }
POST /api/v1/rbac/permissions  { "name": "roles:write" }

# 3. Assign permissions to the role
POST /api/v1/rbac/roles/{admin_role_id}/permissions/{users_read_id}
POST /api/v1/rbac/roles/{admin_role_id}/permissions/{users_write_id}
...

# 4. Assign role to the user
POST /api/v1/rbac/users/{user_id}/roles/{admin_role_id}
```
