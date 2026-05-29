import uuid
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime
from sqlmodel import Field, SQLModel


class ServiceClient(SQLModel, table=True):
    __tablename__ = "service_clients"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    service_id: str = Field(unique=True, index=True, nullable=False)
    secret_hash: str = Field(nullable=False)
    is_active: bool = Field(default=True, nullable=False)
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
