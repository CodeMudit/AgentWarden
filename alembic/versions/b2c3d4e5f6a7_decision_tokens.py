"""Add decision_tokens table.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-10-12

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b2c3d4e5f6a7"
down_revision: str | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "decision_tokens",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("action_id", sa.Integer(), nullable=False),
        sa.Column("agent_id", sa.Integer(), nullable=False),
        sa.Column("tool", sa.String(length=128), nullable=False),
        sa.Column("params_hash", sa.String(length=64), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=True),
        sa.Column("nonce", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["action_id"], ["action_requests.id"]),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_decision_tokens_token_hash", "decision_tokens", ["token_hash"])
    op.create_index("ix_decision_tokens_action_id", "decision_tokens", ["action_id"])
    op.create_index("ix_decision_tokens_agent_id", "decision_tokens", ["agent_id"])


def downgrade() -> None:
    op.drop_index("ix_decision_tokens_agent_id", table_name="decision_tokens")
    op.drop_index("ix_decision_tokens_action_id", table_name="decision_tokens")
    op.drop_index("ix_decision_tokens_token_hash", table_name="decision_tokens")
    op.drop_table("decision_tokens")
