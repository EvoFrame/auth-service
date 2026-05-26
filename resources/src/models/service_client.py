import uuid
from datetime import datetime

from sqlmodel import Field, SQLModel


class ServiceClient(SQLModel, table=True):
    __tablename__ = "service_clients"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    service_id: str = Field(unique=True, index=True, nullable=False)
    secret_hash: str = Field(nullable=False)
    is_active: bool = Field(default=True, nullable=False)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        nullable=False,
        sa_column_kwargs={"onupdate": datetime.utcnow},
    )
