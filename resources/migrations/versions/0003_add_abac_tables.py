"""add ABAC tables: user_attributes, policies, policy_conditions

Revision ID: 0003_add_abac_tables
Revises: 0002_soft_delete
Create Date: 2026-06-05

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_add_abac_tables"
down_revision: str | None = "0002_soft_delete"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "user_attributes",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("user_id", "key"),
    )
    op.create_index("ix_user_attributes_user_id", "user_attributes", ["user_id"])

    op.create_table(
        "policies",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("effect", sa.String(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_policies_name", "policies", ["name"], unique=True)
    op.create_index("ix_policies_is_active", "policies", ["is_active"])

    op.create_table(
        "policy_conditions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("policy_id", sa.UUID(), nullable=False),
        sa.Column("attribute_source", sa.String(), nullable=False),
        sa.Column("attribute_key", sa.String(), nullable=False),
        sa.Column("operator", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_policy_conditions_policy_id", "policy_conditions", ["policy_id"])


def downgrade() -> None:
    op.drop_index("ix_policy_conditions_policy_id", table_name="policy_conditions")
    op.drop_table("policy_conditions")

    op.drop_index("ix_policies_is_active", table_name="policies")
    op.drop_index("ix_policies_name", table_name="policies")
    op.drop_table("policies")

    op.drop_index("ix_user_attributes_user_id", table_name="user_attributes")
    op.drop_table("user_attributes")
