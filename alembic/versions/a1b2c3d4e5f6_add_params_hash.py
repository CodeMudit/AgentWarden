"""Add params_hash to action_requests.

Revision ID: a1b2c3d4e5f6
Revises: 8e0ee0837578
Create Date: 2026-10-12

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: str | None = "8e0ee0837578"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("action_requests") as batch:
        batch.add_column(sa.Column("params_hash", sa.String(length=64), nullable=True))
        batch.create_index("ix_action_requests_params_hash", ["params_hash"])


def downgrade() -> None:
    with op.batch_alter_table("action_requests") as batch:
        batch.drop_index("ix_action_requests_params_hash")
        batch.drop_column("params_hash")
