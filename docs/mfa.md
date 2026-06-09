# MFA — Multi-Factor Authentication

This document describes the TOTP-based MFA system built into `auth-service`, how it
works internally, and how users enable, verify, and disable it.

---

## Overview

MFA is implemented as **TOTP** (Time-based One-Time Password, RFC 6238), compatible with
any standard authenticator app (Google Authenticator, Authy, 1Password, etc.).

Enabling MFA is a **two-step process**: the user first calls `/enable` to receive a
provisioning URI, then calls `/verify` with a valid 6-digit code to activate it. Until
`/verify` succeeds, MFA is not active and no code is required at login.

Once active, every call to `POST /api/v1/users/login` requires a `totp_code` field in
the request body.

---

## TOTP secret storage

The raw TOTP secret is **never stored in plaintext**. It is encrypted with
[Fernet](https://cryptography.io/en/latest/fernet/) (AES-128-CBC + HMAC-SHA256) using
the `TOTP_ENCRYPTION_KEY` environment variable before being persisted in
`users.totp_secret_enc`.

The key must be a URL-safe base64-encoded 32-byte value. Generate one with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## Enable flow

```
1. POST /api/v1/users/me/mfa/enable
   → generates a random TOTP secret
   → encrypts it and stores it in users.totp_secret_enc
   → returns { totp_uri, secret }   (secret shown once — user scans QR or copies it)

2. User adds the account to their authenticator app

3. POST /api/v1/users/me/mfa/verify  { code: "123456" }
   → verifies the code (valid_window=1, i.e. ±30 s tolerance)
   → sets users.mfa_enabled = true
   → publishes auth.user.mfa_changed { action: "enabled" }
```

---

## Login with MFA

When `mfa_enabled = true`, `POST /api/v1/users/login` **requires** a `totp_code`:

```json
{
  "email": "user@example.com",
  "password": "s3cr3t",
  "totp_code": "123456"
}
```

If `totp_code` is absent, the server returns `403 MFA_REQUIRED`. If the code is invalid,
it returns `401 INVALID_TOTP`.

Credential verification (password) always happens before the TOTP check.

---

## Disable flow

```
POST /api/v1/users/me/mfa/disable  { code: "123456" }
  → verifies the current TOTP code
  → sets users.mfa_enabled = false
  → clears users.totp_secret_enc
  → publishes auth.user.mfa_changed { action: "disabled" }
```

The user must supply a valid code to disable MFA, preventing an attacker with a stolen
session from silently turning it off.

---

## API reference

All endpoints require a valid `Authorization: Bearer <access_token>` and a valid
`X-Service-Token`.

| Method | Path                           | Description                               |
| ------ | ------------------------------ | ----------------------------------------- |
| `POST` | `/api/v1/users/me/mfa/enable`  | Generate TOTP secret and provisioning URI |
| `POST` | `/api/v1/users/me/mfa/verify`  | Verify code and activate MFA              |
| `POST` | `/api/v1/users/me/mfa/disable` | Disable MFA (requires valid TOTP code)    |

**Enable response:**

```json
{
  "totp_uri": "otpauth://totp/auth-service:user%40example.com?secret=BASE32SECRET&issuer=auth-service",
  "secret": "BASE32SECRET"
}
```

**Verify / disable request body:**

```json
{ "code": "123456" }
```

---

## Domain events

| Stream                  | Published when                                               |
| ----------------------- | ------------------------------------------------------------ |
| `auth.user.mfa_changed` | MFA enabled or disabled (`action: "enabled"` / `"disabled"`) |

---

## Security notes

- The TOTP secret is shown to the user **once** (on `/enable`) and then only stored
  encrypted. If lost, the user must disable and re-enable MFA.
- The TOTP window is `±1` interval (30 s grace period on each side), following RFC 6238
  recommendations for clock skew.
- Disabling MFA requires proving possession of the current code, preventing session
  hijacking from silently removing MFA.
- If `TOTP_ENCRYPTION_KEY` is not configured, the endpoint returns `500 MFA_NOT_AVAILABLE`.
