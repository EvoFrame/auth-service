from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", ".env.local"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Identity
    SERVICE_NAME: str = "auth-service"
    SERVICE_VERSION: str = "0.1.0"
    SERVICE_ID: str = "auth-service"
    SERVICE_SECRET: str

    # Database
    DATABASE_URL: str

    # Redis
    REDIS_URL: str

    # JWT / Keys — auth-service is the ONLY service that holds the private key
    RS256_PRIVATE_KEY: str
    RS256_PUBLIC_KEY: str

    @field_validator("RS256_PRIVATE_KEY", "RS256_PUBLIC_KEY", mode="before")
    @classmethod
    def expand_newlines(cls, v: str) -> str:
        """Allow PEM keys stored as single-line strings with literal \\n escapes."""
        return v.replace("\\n", "\n")
    ACCESS_TOKEN_TTL: int = 900        # 15 min — user access tokens
    SERVICE_TOKEN_TTL: int = 300       # 5 min  — M2M service tokens
    REFRESH_TOKEN_TTL: int = 2592000   # 30 days

    # Password hashing (Argon2)
    ARGON2_TIME_COST: int = 2
    ARGON2_MEMORY_COST: int = 65536
    ARGON2_PARALLELISM: int = 2

    # TOTP secret encryption — Fernet key (base64-encoded 32-byte key)
    TOTP_ENCRYPTION_KEY: str = ""

    # OAuth2 providers
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    OAUTH_REDIRECT_BASE_URL: str = "http://localhost:8080"

    # Runtime
    APP_ENV: str = "production"
    WORKERS: int = 4
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    # Dev-only: bypass X-Service-Token validation. Ignored unless DEBUG=true.
    SKIP_SERVICE_AUTH: bool = False


settings = Settings()
