import uuid
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime
from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    email: str = Field(unique=True, index=True, nullable=False)
    password_hash: str = Field(nullable=False)
    is_active: bool = Field(default=True, nullable=False)
    is_verified: bool = Field(default=False, nullable=False)
    mfa_enabled: bool = Field(default=False, nullable=False)
    totp_secret_enc: str | None = Field(default=None, nullable=True)
    backup_email: str | None = Field(default=None, nullable=True, unique=True, index=True)
    backup_email_verified: bool = Field(default=False, nullable=False)
    deleted_at: datetime | None = Field(sa_column=Column(DateTime(timezone=True), nullable=True, default=None))
    created_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))
    )
    updated_at: datetime = Field(
        sa_column=Column(
            DateTime(timezone=True),
            nullable=False,
            default=lambda: datetime.now(UTC),
            onupdate=lambda: datetime.now(UTC),
        )
    )
