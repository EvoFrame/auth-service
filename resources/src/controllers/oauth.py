"""OAuth2 controller — social login via authlib (Google, GitHub)."""

import structlog
from authlib.integrations.httpx_client import AsyncOAuth2Client
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.controllers.auth import _get_user_roles, _issue_access_token, _ph
from src.libs.errors import AppError
from src.models.user import User

logger = structlog.get_logger()

_PROVIDERS = {
    "google": {
        "client_id_key": "GOOGLE_CLIENT_ID",
        "client_secret_key": "GOOGLE_CLIENT_SECRET",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        "email_field": "email",
    },
    "github": {
        "client_id_key": "GITHUB_CLIENT_ID",
        "client_secret_key": "GITHUB_CLIENT_SECRET",
        "token_endpoint": "https://github.com/login/oauth/access_token",
        "userinfo_endpoint": "https://api.github.com/user",
        "email_field": "email",
    },
}


async def oauth_login(
    provider: str,
    code: str,
    session: AsyncSession,
) -> dict:
    cfg = _PROVIDERS.get(provider)
    if not cfg:
        raise AppError("UNSUPPORTED_PROVIDER", f"OAuth provider '{provider}' is not supported.", status_code=400)

    client_id = getattr(settings, cfg["client_id_key"])
    client_secret = getattr(settings, cfg["client_secret_key"])

    if not client_id or not client_secret:
        raise AppError("PROVIDER_NOT_CONFIGURED", f"OAuth provider '{provider}' is not configured.", status_code=503)

    redirect_uri = f"{settings.OAUTH_REDIRECT_BASE_URL}/auth/oauth/{provider}/callback"

    async with AsyncOAuth2Client(client_id=client_id, client_secret=client_secret) as client:
        await client.fetch_token(
            cfg["token_endpoint"],
            code=code,
            redirect_uri=redirect_uri,
            headers={"Accept": "application/json"},
        )
        userinfo_resp = await client.get(cfg["userinfo_endpoint"])
        userinfo_resp.raise_for_status()
        userinfo = userinfo_resp.json()

    email = userinfo.get(cfg["email_field"])
    if not email:
        raise AppError("OAUTH_NO_EMAIL", "Could not retrieve email from OAuth provider.", status_code=400)

    user = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if not user:
        import secrets as _secrets

        user = User(
            email=email,
            password_hash=_ph.hash(_secrets.token_urlsafe(32)),
            is_verified=True,
            is_active=True,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        logger.info("oauth_user_created", user_id=str(user.id), provider=provider)

    if not user.is_active:
        raise AppError("ACCOUNT_DISABLED", "This account has been disabled.", status_code=403)

    roles = await _get_user_roles(user.id, session)
    access_token, _ = _issue_access_token(user, roles)

    return {"access_token": access_token, "token_type": "bearer", "expires_in": settings.ACCESS_TOKEN_TTL}
