# ABAC — Attribute-Based Access Control

This document describes the ABAC system built into `auth-service`, how it works internally,
and how internal services should use it.

---

## Overview

ABAC is a **pull-model** authorization system. Internal services do not enforce access
decisions themselves — they ask `auth-service` to evaluate a request and act on the verdict.

```
[Internal service]
  → POST /api/v1/abac/evaluate
    { user_id, action, resource_type, resource_attributes, environment_attributes }
  ← { decision: "allow" | "deny", matched_policy_name, reason }
```

Because `auth-service` is not directly exposed (it sits behind the API Gateway and all
callers must present a valid `X-Service-Token`), the `caller_service` identity is always
extracted server-side from the token and injected into the evaluation context. Callers
**cannot spoof it**.

---

## Default behaviour

**Default deny, fail-closed.** If no policy matches the request, the answer is always `deny`.
An explicit `deny` policy always overrides any `allow` policy, regardless of priority.

---

## Core concepts

### User attributes

Arbitrary key/value string pairs attached to a user, stored in `user_attributes`.

```
user_id  | key               | value
---------|-------------------|--------
<uuid>   | department        | engineering
<uuid>   | clearance_level   | 3
<uuid>   | status            | active
```

These are the primary source for subject-level conditions. In addition to stored attributes,
the evaluation engine automatically injects the following derived fields into the subject
bag at evaluation time:

| Key | Source |
|---|---|
| `is_active` | `users.is_active` |
| `is_verified` | `users.is_verified` |
| `mfa_enabled` | `users.mfa_enabled` |
| `roles` | JSON-encoded list of the user's role names |
| `permissions` | JSON-encoded list of all permissions derived from roles |

### Policies

A policy has an `effect` (`allow` or `deny`), a `priority` (higher = evaluated first),
an `is_active` toggle, and a list of conditions.

A policy **fires** only when:

1. It is active (`is_active = true`)
2. It has **at least one condition**
3. **All** its conditions match the evaluation context (AND logic)

Policies with zero conditions never fire.

### Policy conditions

Each condition targets one attribute in one of three **attribute sources**:

| Source | What it contains |
|---|---|
| `subject` | User attributes (stored + derived) |
| `resource` | Attributes of the resource being accessed (supplied by the calling service) |
| `environment` | Ambient context: `action`, `resource_type`, `caller_service`, plus any extras the calling service adds |

A condition is defined by:

```
attribute_source  attribute_key    operator  value
subject           department       eq        engineering
environment       caller_service   in        ["api-gateway","worker-service"]
resource          owner_id         eq        <some-uuid>
```

A condition can also compare an attribute against **another attribute** from any bag instead
of a hard-coded literal. Use `value_ref_source` and `value_ref_key` for this:

```
attribute_source  attribute_key  operator  value_ref_source  value_ref_key
subject           user_id        eq        resource          owner_id
```

This fires only when `subject["user_id"] == resource["owner_id"]` at evaluation time.
`value_ref_source` and `value_ref_key` must both be set or both be absent.

#### Supported operators

| Operator | Description | Value format |
|---|---|---|
| `eq` | Exact string equality | plain string |
| `neq` | Not equal | plain string |
| `in` | Attribute value is in a list | JSON array, e.g. `["a","b"]` |
| `not_in` | Attribute value is not in a list | JSON array |
| `contains` | Attribute value contains the substring | plain string |
| `gt` | Greater than (numeric coercion) | numeric string |
| `lt` | Less than (numeric coercion) | numeric string |
| `gte` | Greater than or equal (numeric coercion) | numeric string |
| `lte` | Less than or equal (numeric coercion) | numeric string |

> All attribute values are strings. Numeric operators (`gt`, `lt`, `gte`, `lte`) coerce
> both sides to `float` before comparing. List operators (`in`, `not_in`) expect the
> condition `value` to be a valid JSON array string.
>
> **Limitation:** `in` / `not_in` are not meaningful with a `value_ref` (the resolved
> attribute is always a scalar string, not a list). Use `eq` / `neq` for cross-attribute
> comparisons.

---

## Evaluation algorithm

```
1. Load all active policies and their conditions from the database
2. Sort by priority descending (higher priority evaluated first)
3. For each policy:
     if all its conditions match the context → policy fires
4. Collect all fired policies
5. If any fired policy has effect=deny  → DENY  (deny always wins)
6. If any fired policy has effect=allow → ALLOW
7. If no policy fired                   → DENY  (default)
```

The engine is implemented as a **pure Python function** with no I/O in
`src/libs/abac_engine.py`. The controller in `src/controllers/abac.py` is responsible
for loading data from the database and building the evaluation context before calling it.

---

## Evaluation context construction

When `POST /abac/evaluate` is called, the controller builds three attribute bags:

### Subject bag

1. All `user_attributes` rows for the user (`key → value`)
2. Derived: `is_active`, `is_verified`, `mfa_enabled` (stringified booleans: `"true"` / `"false"`)
3. Derived: `roles` (JSON array of role names), `permissions` (JSON array of permission names)

### Resource bag

Passed verbatim from `resource_attributes` in the request body.

### Environment bag

Built from `environment_attributes` in the request body, then **server-side overrides**:

| Key | Value | Overridable by caller? |
|---|---|---|
| `caller_service` | Extracted from `X-Service-Token` JWT | ❌ No |
| `action` | From request body | ✅ Yes |
| `resource_type` | From request body | ✅ Yes |

---

## API reference

All endpoints require a valid `X-Service-Token` (enforced by `ServiceAuthMiddleware`) and
an appropriate ABAC permission in the user's `Authorization` bearer token.

### Evaluation

| Method | Path | Permission | Description |
|---|---|---|---|
| `POST` | `/api/v1/abac/evaluate` | `abac:evaluate` | Evaluate a request and get a decision |

**Request body:**

```json
{
  "user_id": "<uuid>",
  "action": "read",
  "resource_type": "document",
  "resource_attributes": {
    "owner_id": "<uuid>",
    "classification": "internal"
  },
  "environment_attributes": {
    "ip_region": "eu-west"
  }
}
```

**Response:**

```json
{
  "decision": "allow",
  "matched_policy_id": "<uuid>",
  "matched_policy_name": "allow-engineering-read",
  "reason": "Allowed by policy 'allow-engineering-read'."
}
```

### User attributes

| Method | Path | Permission |
|---|---|---|
| `GET` | `/api/v1/abac/users/{user_id}/attributes` | `abac:read` |
| `PUT` | `/api/v1/abac/users/{user_id}/attributes/{key}` | `abac:write` |
| `DELETE` | `/api/v1/abac/users/{user_id}/attributes/{key}` | `abac:write` |

### Policy management

| Method | Path | Permission |
|---|---|---|
| `GET` | `/api/v1/abac/policies` | `abac:read` |
| `POST` | `/api/v1/abac/policies` | `abac:write` |
| `GET` | `/api/v1/abac/policies/{policy_id}` | `abac:read` |
| `PATCH` | `/api/v1/abac/policies/{policy_id}` | `abac:write` |
| `DELETE` | `/api/v1/abac/policies/{policy_id}` | `abac:write` |

### Condition management

| Method | Path | Permission |
|---|---|---|
| `POST` | `/api/v1/abac/policies/{policy_id}/conditions` | `abac:write` |
| `DELETE` | `/api/v1/abac/conditions/{condition_id}` | `abac:write` |

---

## Data model

```
user_attributes
├── user_id      UUID   (composite PK)
├── key          TEXT   (composite PK)
├── value        TEXT
└── created_at   TIMESTAMPTZ

policies
├── id           UUID   PK
├── name         TEXT   UNIQUE
├── description  TEXT?
├── effect       TEXT   "allow" | "deny"
├── priority     INT    higher = evaluated first
├── is_active    BOOL
└── created_at   TIMESTAMPTZ

policy_conditions
├── id                UUID   PK
├── policy_id         UUID   FK → policies.id
├── attribute_source  TEXT   "subject" | "resource" | "environment"
├── attribute_key     TEXT
├── operator          TEXT   eq | neq | in | not_in | contains | gt | lt | gte | lte
├── value             TEXT   literal value (or empty string when value_ref is used)
├── value_ref_source  TEXT?  resolve RHS dynamically from this bag
└── value_ref_key     TEXT?  attribute key to look up in value_ref_source bag
```

---

## Example: allow engineering users to read internal documents

```
Policy: "allow-engineering-read"
  effect:    allow
  priority:  10
  is_active: true

Conditions:
  subject.department      eq   engineering
  resource.classification eq   internal
  environment.action      eq   read
```

With this policy, the following request will return `allow`:

```json
{
  "user_id": "<uuid of a user with department=engineering>",
  "action": "read",
  "resource_type": "document",
  "resource_attributes": { "classification": "internal" }
}
```

And this will return `deny` (wrong action):

```json
{
  "user_id": "<uuid of a user with department=engineering>",
  "action": "delete",
  "resource_type": "document",
  "resource_attributes": { "classification": "internal" }
}
```

---

## Example: allow a user to access their own file (cross-attribute comparison)

```
Policy: "allow-owner-read"
  effect:    allow
  priority:  20
  is_active: true

Conditions:
  subject.user_id  eq  resource.owner_id   ← value_ref_source=resource, value_ref_key=owner_id
  environment.action  eq  read
```

For this to work, each user must have a `user_id` attribute set (e.g. equal to their UUID):

```bash
PUT /api/v1/abac/users/{user_id}/attributes/user_id
{ "value": "<user_id>" }
```

Then the calling service (e.g. `file-service`) includes the file's owner in the request:

```json
{
  "user_id": "<requesting user uuid>",
  "action": "read",
  "resource_type": "file",
  "resource_attributes": { "owner_id": "<file owner uuid>" }
}
```

If `subject["user_id"] == resource["owner_id"]` → `allow`. Otherwise → `deny`.

---

## Coexistence with RBAC

ABAC and RBAC are independent systems. A service can use either or both:

- **RBAC** (`require_permission`) — coarse-grained, role-based, enforced inside `auth-service` itself
- **ABAC** (`POST /abac/evaluate`) — fine-grained, attribute-based, enforced by the **calling service** acting on the verdict

The user's RBAC roles and permissions are automatically included in the `subject` bag
during ABAC evaluation (as `roles` and `permissions` JSON arrays), so it is possible to
write ABAC policies that also inspect role membership.

---

## Security notes

- `caller_service` is always set server-side from the validated `X-Service-Token` JWT.
  A calling service cannot impersonate another service in ABAC conditions.
- Policies with **no conditions** never fire. A newly created policy is inert until at
  least one condition is added.
- Deactivating a policy (`is_active: false`) is instant and affects the next evaluation
  call. No cache invalidation is needed (evaluation always reads from the database).
