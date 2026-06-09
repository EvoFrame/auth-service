"""add scope columns to policies for DB-level pre-filtering

Revision ID: 0005_add_policy_scope_columns
Revises: 0004_add_condition_value_ref
Create Date: 2026-06-09

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_add_policy_scope_columns"
down_revision: str | None = "0004_add_condition_value_ref"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("policies", sa.Column("scope_resource_type", sa.String(), nullable=True))
    op.add_column("policies", sa.Column("scope_action", sa.String(), nullable=True))
    # Partial indexes — only index rows that actually have a scope set
    op.create_index(
        "ix_policies_scope_resource_type",
        "policies",
        ["scope_resource_type"],
        postgresql_where=sa.text("scope_resource_type IS NOT NULL"),
    )
    op.create_index(
        "ix_policies_scope_action",
        "policies",
        ["scope_action"],
        postgresql_where=sa.text("scope_action IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_policies_scope_action", table_name="policies")
    op.drop_index("ix_policies_scope_resource_type", table_name="policies")
    op.drop_column("policies", "scope_action")
    op.drop_column("policies", "scope_resource_type")
