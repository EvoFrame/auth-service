"""Unit tests: TOTP MFA enable / verify / disable flow."""

import pyotp
import pytest
from cryptography.fernet import Fernet

from src.config.settings import settings
from src.controllers.mfa import _check_totp, mfa_disable, mfa_enable, mfa_verify_and_activate
from src.libs.errors import AppError
from src.models.user import User

pytestmark = pytest.mark.asyncio(loop_scope="session")


def _make_user(**kwargs) -> User:
    import uuid

    defaults = {
        "id": uuid.uuid4(),
        "email": "mfa_user@example.com",
        "password_hash": "hash",
        "is_active": True,
        "is_verified": True,
        "mfa_enabled": False,
        "totp_secret_enc": None,
    }
    defaults.update(kwargs)
    return User(**defaults)


class _FakeSession:
    """Minimal async session stub for unit tests."""

    async def commit(self):
        pass


class _FakePublisher:
    def __init__(self):
        self.events: list[tuple] = []

    async def publish(self, event: str, payload: dict, **kwargs):
        self.events.append((event, payload))


# ── enable ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mfa_enable_returns_uri_and_secret():
    user = _make_user()
    result = await mfa_enable(user, _FakeSession())
    assert result.secret
    assert "otpauth://" in result.totp_uri
    assert user.totp_secret_enc is not None


@pytest.mark.asyncio
async def test_mfa_enable_raises_if_already_enabled():
    user = _make_user(mfa_enabled=True)
    with pytest.raises(AppError) as exc:
        await mfa_enable(user, _FakeSession())
    assert exc.value.code == "MFA_ALREADY_ENABLED"


# ── verify & activate ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mfa_verify_activates_mfa():
    user = _make_user()
    await mfa_enable(user, _FakeSession())

    # Decrypt secret and generate a valid TOTP code
    fernet = Fernet(settings.TOTP_ENCRYPTION_KEY.encode())
    secret = fernet.decrypt(user.totp_secret_enc.encode()).decode()
    code = pyotp.TOTP(secret).now()

    from src.schemas.mfa import MFAVerifyRequest

    body = MFAVerifyRequest(code=code)
    pub = _FakePublisher()
    result = await mfa_verify_and_activate(user, body, _FakeSession(), pub)
    assert user.mfa_enabled is True
    assert any(e[0] == "auth.user.mfa_changed" for e in pub.events)
    assert "message" in result


@pytest.mark.asyncio
async def test_mfa_verify_invalid_code_raises():
    user = _make_user()
    await mfa_enable(user, _FakeSession())

    from src.schemas.mfa import MFAVerifyRequest

    body = MFAVerifyRequest(code="000000")
    with pytest.raises(AppError) as exc:
        await mfa_verify_and_activate(user, body, _FakeSession(), _FakePublisher())
    assert exc.value.code == "INVALID_TOTP"


# ── disable ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mfa_disable_clears_secret():
    user = _make_user()
    await mfa_enable(user, _FakeSession())

    # activate
    fernet = Fernet(settings.TOTP_ENCRYPTION_KEY.encode())
    secret = fernet.decrypt(user.totp_secret_enc.encode()).decode()
    code = pyotp.TOTP(secret).now()

    from src.schemas.mfa import MFADisableRequest, MFAVerifyRequest

    await mfa_verify_and_activate(user, MFAVerifyRequest(code=code), _FakeSession(), _FakePublisher())
    assert user.mfa_enabled

    # generate a fresh code for disable
    disable_code = pyotp.TOTP(secret).now()
    pub = _FakePublisher()
    await mfa_disable(user, MFADisableRequest(code=disable_code), _FakeSession(), pub)

    assert user.mfa_enabled is False
    assert user.totp_secret_enc is None
    assert any(e[0] == "auth.user.mfa_changed" for e in pub.events)


@pytest.mark.asyncio
async def test_mfa_disable_raises_if_not_enabled():
    user = _make_user(mfa_enabled=False)

    from src.schemas.mfa import MFADisableRequest

    with pytest.raises(AppError) as exc:
        await mfa_disable(user, MFADisableRequest(code="123456"), _FakeSession(), _FakePublisher())
    assert exc.value.code == "MFA_NOT_ENABLED"


# ── _check_totp helper ────────────────────────────────────────────────────────


async def test_check_totp_raises_when_no_secret():
    user = _make_user(totp_secret_enc=None)
    with pytest.raises(AppError) as exc:
        _check_totp(user, "000000")
    assert exc.value.code == "MFA_NOT_CONFIGURED"
