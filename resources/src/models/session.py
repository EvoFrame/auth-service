import uuid
from datetime import datetime

from sqlmodel import Field, SQLModel


class RefreshSession(SQLModel, table=True):
    __tablename__ = "refresh_sessions"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: uuid.UUID = Field(nullable=False, index=True)
    token_hash: str = Field(nullable=False, index=True)
    expires_at: datetime = Field(nullable=False)
    revoked_at: datetime | None = Field(default=None, nullable=True)
    ip: str | None = Field(default=None, nullable=True)
    user_agent: str | None = Field(default=None, nullable=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
