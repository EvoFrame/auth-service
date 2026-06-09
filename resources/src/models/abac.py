import uuid
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import Column, DateTime
from sqlmodel import Field, SQLModel

AttributeSource = Literal["subject", "resource", "environment"]
PolicyEffect = Literal["allow", "deny"]
ConditionOperator = Literal["eq", "neq", "in", "not_in", "contains", "gt", "lt", "gte", "lte"]


class UserAttribute(SQLModel, table=True):
    __tablename__ = "user_attributes"

    user_id: uuid.UUID = Field(primary_key=True)
    key: str = Field(primary_key=True)
    value: str = Field(nullable=False)
    # Audit columns — always last
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


class Policy(SQLModel, table=True):
    __tablename__ = "policies"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(unique=True, index=True, nullable=False)
    description: str | None = Field(default=None, nullable=True)
    effect: str = Field(nullable=False)  # "allow" | "deny"
    priority: int = Field(default=0, nullable=False)
    is_active: bool = Field(default=True, nullable=False)
    scope_resource_type: str | None = Field(default=None, nullable=True)  # NULL = all resource types
    scope_action: str | None = Field(default=None, nullable=True)  # NULL = all actions
    # Audit columns — always last
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


class PolicyCondition(SQLModel, table=True):
    __tablename__ = "policy_conditions"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    policy_id: uuid.UUID = Field(foreign_key="policies.id", nullable=False, index=True)
    attribute_source: str = Field(nullable=False)  # "subject" | "resource" | "environment"
    attribute_key: str = Field(nullable=False)
    operator: str = Field(nullable=False)
    value: str = Field(nullable=False)  # raw string or JSON-encoded list for in/not_in
    value_ref_source: str | None = Field(default=None, nullable=True)  # "subject"|"resource"|"environment"
    value_ref_key: str | None = Field(default=None, nullable=True)  # attribute key to resolve
    # Audit columns — always last
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
