"""MFA controller — TOTP enable, verify, disable."""

import pyotp
import structlog
from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.events.publisher import EventPublisher
from src.libs.errors import AppError
from src.models.user import User
from src.schemas.mfa import MFADisableRequest, MFAEnableResponse, MFAVerifyRequest

logger = structlog.get_logger()


def _fernet() -> Fernet:
    """Return a configured Fernet instance using the TOTP encryption key.

    Returns:
        A Fernet instance ready for encrypt/decrypt operations.

    Raises:
        AppError: If TOTP_ENCRYPTION_KEY is not set in settings (500).
    """
    if not settings.TOTP_ENCRYPTION_KEY:
        raise AppError("MFA_NOT_AVAILABLE", "TOTP encryption key not configured.", status_code=500)
    return Fernet(settings.TOTP_ENCRYPTION_KEY.encode())


async def mfa_enable(user: User, session: AsyncSession) -> MFAEnableResponse:
    """Generate a new TOTP secret and store it encrypted, awaiting verification.

    Args:
        user: The authenticated user enabling MFA.
        session: Active database session.

    Returns:
        An MFAEnableResponse with the provisioning URI and raw secret.

    Raises:
        AppError: If MFA is already enabled for this user (409).
    """
    if user.mfa_enabled:
        raise AppError("MFA_ALREADY_ENABLED", "MFA is already enabled.", status_code=409)

    secret = pyotp.random_base32()
    enc_secret = _fernet().encrypt(secret.encode()).decode()

    user.totp_secret_enc = enc_secret
    await session.commit()

    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=settings.SERVICE_NAME)
    return MFAEnableResponse(totp_uri=totp_uri, secret=secret)


async def mfa_verify_and_activate(
    user: User,
    body: MFAVerifyRequest,
    session: AsyncSession,
    publisher: EventPublisher,
) -> dict:
    """Verify the TOTP code and mark MFA as fully enabled.

    Args:
        user: The authenticated user completing MFA setup.
        body: Request body containing the 6-digit TOTP verification code.
        session: Active database session.
        publisher: Event publisher for dispatching the MFA-changed event.

    Returns:
        A dict with a success message.

    Raises:
        AppError: If MFA is already enabled, not configured, or the code is invalid.
    """
    if user.mfa_enabled:
        raise AppError("MFA_ALREADY_ENABLED", "MFA is already enabled.", status_code=409)

    if not user.totp_secret_enc:
        raise AppError("MFA_NOT_CONFIGURED", "Call /auth/mfa/enable first.", status_code=400)

    _check_totp(user, body.code)

    user.mfa_enabled = True
    await session.commit()

    await publisher.publish("auth.user.mfa_changed", {"user_id": str(user.id), "action": "enabled"})
    logger.info("mfa_enabled", user_id=str(user.id))
    return {"message": "MFA enabled successfully."}


async def mfa_disable(
    user: User,
    body: MFADisableRequest,
    session: AsyncSession,
    publisher: EventPublisher,
) -> dict:
    """Disable TOTP MFA for the user after verifying the current code.

    Args:
        user: The authenticated user disabling MFA.
        body: Request body containing the current 6-digit TOTP code.
        session: Active database session.
        publisher: Event publisher for dispatching the MFA-changed event.

    Returns:
        A dict with a success message.

    Raises:
        AppError: If MFA is not enabled or the TOTP code is invalid.
    """
    if not user.mfa_enabled:
        raise AppError("MFA_NOT_ENABLED", "MFA is not enabled.", status_code=400)

    _check_totp(user, body.code)

    user.mfa_enabled = False
    user.totp_secret_enc = None
    await session.commit()

    await publisher.publish("auth.user.mfa_changed", {"user_id": str(user.id), "action": "disabled"})
    logger.info("mfa_disabled", user_id=str(user.id))
    return {"message": "MFA disabled successfully."}


def _check_totp(user: User, code: str) -> None:
    """Validate a TOTP code against the user's stored encrypted secret.

    Args:
        user: The user whose TOTP secret to verify against.
        code: The 6-digit TOTP code to validate.

    Raises:
        AppError: If MFA is not configured or the TOTP code is invalid.
    """
    if not user.totp_secret_enc:
        raise AppError("MFA_NOT_CONFIGURED", "MFA is not configured.", status_code=400)

    secret = _fernet().decrypt(user.totp_secret_enc.encode()).decode()
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        raise AppError("INVALID_TOTP", "Invalid TOTP code.", status_code=401)
