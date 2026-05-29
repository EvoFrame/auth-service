"""soft delete for users and service_clients

Revision ID: 0002_soft_delete
Revises: 0001_initial
Create Date: 2026-05-29

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_soft_delete"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_users_deleted_at", "users", ["deleted_at"])

    op.add_column("service_clients", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_service_clients_deleted_at", "service_clients", ["deleted_at"])


def downgrade() -> None:
    op.drop_index("ix_service_clients_deleted_at", table_name="service_clients")
    op.drop_column("service_clients", "deleted_at")

    op.drop_index("ix_users_deleted_at", table_name="users")
    op.drop_column("users", "deleted_at")
