# OAuth2 — Social Login

This document describes the OAuth2 social login feature built into `auth-service`,
supporting Google and GitHub as identity providers.

---

## Overview

OAuth2 social login allows users to authenticate using an existing Google or GitHub
account instead of a password. The flow is **authorization-code-based**: the client
(typically the API Gateway or a frontend) handles the browser redirect and callback, then
forwards the authorization code to `auth-service`, which exchanges it for a user access
token.

```
[Browser]
  → redirected to provider (Google / GitHub)
  → authenticates and consents
  → provider redirects to callback URL with ?code=...

[Client / API Gateway]
  → POST /api/v1/users/oauth/{provider}?code=<code>
  ← { access_token, token_type, expires_in }
```

`auth-service` performs the code exchange directly with the provider (server-side) and
returns a standard user access token. The provider's tokens are never surfaced to the
client.

---

## Supported providers

| Provider | `{provider}` value | Required env vars                          |
| -------- | ------------------ | ------------------------------------------ |
| Google   | `google`           | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` |
| GitHub   | `github`           | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` |

If the required credentials are not configured, the endpoint returns `503 PROVIDER_NOT_CONFIGURED`.

---

## Account creation

When a user logs in via OAuth for the first time, `auth-service` **automatically creates
an account**:

- `email` is set to the verified primary email from the provider.
- `password_hash` is set to a random secret (the user cannot log in with a password).
- `is_verified` is set to `true` (the email is already confirmed by the provider).
- `is_active` is set to `true`.

On subsequent logins the existing account is found by email and a new access token is
issued. The user cannot set a password for an OAuth-created account through the standard
password reset flow (the reset email would still go to the same address, which is valid).

---

## GitHub email resolution

GitHub users can set their email to private. In that case the `/user` API endpoint
returns `null` for the email field. `auth-service` falls back to `GET /user/emails` and
picks the **primary verified** address. If no verified primary email can be found, the
request fails with `400 OAUTH_NO_EMAIL`.

---

## Redirect URI

The redirect URI sent to the provider during the code exchange is built as:

```
{OAUTH_REDIRECT_BASE_URL}/auth/oauth/{provider}/callback
```

`OAUTH_REDIRECT_BASE_URL` defaults to `http://localhost:8080` and must be set to the
base URL of the component that receives the OAuth callback (typically the API Gateway).

This URI must be registered in the OAuth application settings of each provider.

---

## API reference

| Method | Path                                         | Auth required            | Description                                     |
| ------ | -------------------------------------------- | ------------------------ | ----------------------------------------------- |
| `POST` | `/api/v1/users/oauth/{provider}?code=<code>` | None (no user token yet) | Exchange authorization code for an access token |

**Response:**

```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "expires_in": 900
}
```

> Note: OAuth login does **not** issue a refresh token. The user must re-authenticate via
> the provider to get a new access token after expiry.

---

## Security notes

- The authorization code is exchanged **server-side** — the provider's client secret
  never leaves `auth-service`.
- Only **verified** primary emails are accepted from GitHub. Unverified addresses are
  rejected.
- Disabled accounts (`is_active = false`) and soft-deleted accounts (`deleted_at IS NOT
NULL`) cannot log in via OAuth.
- The `X-Service-Token` requirement (enforced by `ServiceAuthMiddleware`) still applies
  to the OAuth endpoint; only known internal services can trigger it.
