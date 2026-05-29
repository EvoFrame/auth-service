"""add backup_email and backup_email_verified to users

Revision ID: 0003_backup_email
Revises: 0002_soft_delete
Create Date: 2026-05-29

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_backup_email"
down_revision: str | None = "0002_soft_delete"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("backup_email", sa.String(), nullable=True))
    op.add_column("users", sa.Column("backup_email_verified", sa.Boolean(), nullable=False, server_default="false"))
    op.create_index("ix_users_backup_email", "users", ["backup_email"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_backup_email", table_name="users")
    op.drop_column("users", "backup_email_verified")
    op.drop_column("users", "backup_email")
