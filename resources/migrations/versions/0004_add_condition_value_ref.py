"""add value_ref columns to policy_conditions for cross-attribute comparison

Revision ID: 0004_add_condition_value_ref
Revises: 0003_add_abac_tables
Create Date: 2026-06-05

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_add_condition_value_ref"
down_revision: str | None = "0003_add_abac_tables"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("policy_conditions", sa.Column("value_ref_source", sa.String(), nullable=True))
    op.add_column("policy_conditions", sa.Column("value_ref_key", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("policy_conditions", "value_ref_key")
    op.drop_column("policy_conditions", "value_ref_source")
