"""PS5 Governance OS models and extensions.

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-10-12

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c3d4e5f6a7b8"
down_revision: str | None = "b2c3d4e5f6a7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Update agents table
    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("risk_category", sa.String(length=16), nullable=False, server_default="medium")
        )
        batch_op.add_column(
            sa.Column("permitted_actions", sa.JSON(), nullable=False, server_default="[]")
        )
        batch_op.add_column(
            sa.Column("data_access", sa.JSON(), nullable=False, server_default="[]")
        )
        batch_op.add_column(
            sa.Column("cost_per_call", sa.Float(), nullable=False, server_default="0.01")
        )
        batch_op.add_column(
            sa.Column("breach_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(sa.Column("status_reason", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("status_updated_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("status_updated_by", sa.String(length=64), nullable=True))

    # 2. Update action_requests table
    with op.batch_alter_table("action_requests", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("data_used", sa.JSON(), nullable=False, server_default="[]")
        )
        batch_op.add_column(
            sa.Column("is_breach", sa.Boolean(), nullable=False, server_default="0")
        )
        batch_op.add_column(sa.Column("breach_reason", sa.Text(), nullable=True))

    # 3. Create work_items table
    op.create_table(
        "work_items",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("task_type", sa.String(length=64), nullable=False),
        sa.Column("assignee_type", sa.String(length=16), nullable=False),
        sa.Column("assignee_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("risk_category", sa.String(length=16), nullable=False, server_default="medium"),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("action_request_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["action_request_id"], ["action_requests.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("work_items", schema=None) as batch_op:
        batch_op.create_index("ix_work_items_task_type", ["task_type"])
        batch_op.create_index("ix_work_items_status", ["status"])
        batch_op.create_index("ix_work_items_created_at", ["created_at"])

    # 4. Create exception_cases table
    op.create_table(
        "exception_cases",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("agent_id", sa.Integer(), nullable=True),
        sa.Column("action_request_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="high"),
        sa.Column("assigned_user_id", sa.Integer(), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.ForeignKeyConstraint(["action_request_id"], ["action_requests.id"]),
        sa.ForeignKeyConstraint(["assigned_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("exception_cases", schema=None) as batch_op:
        batch_op.create_index("ix_exception_cases_agent_id", ["agent_id"])
        batch_op.create_index("ix_exception_cases_action_request_id", ["action_request_id"])
        batch_op.create_index("ix_exception_cases_status", ["status"])
        batch_op.create_index("ix_exception_cases_created_at", ["created_at"])

    # 5. Create incidents table
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("agent_id", sa.Integer(), nullable=True),
        sa.Column("action_request_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="high"),
        sa.Column("created_by_user_id", sa.Integer(), nullable=False),
        sa.Column("assigned_user_id", sa.Integer(), nullable=True),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.ForeignKeyConstraint(["action_request_id"], ["action_requests.id"]),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["assigned_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.create_index("ix_incidents_agent_id", ["agent_id"])
        batch_op.create_index("ix_incidents_action_request_id", ["action_request_id"])
        batch_op.create_index("ix_incidents_status", ["status"])
        batch_op.create_index("ix_incidents_created_at", ["created_at"])


def downgrade() -> None:
    op.drop_table("incidents")
    op.drop_table("exception_cases")
    op.drop_table("work_items")
    with op.batch_alter_table("action_requests", schema=None) as batch_op:
        batch_op.drop_column("breach_reason")
        batch_op.drop_column("is_breach")
        batch_op.drop_column("data_used")
    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.drop_column("status_updated_by")
        batch_op.drop_column("status_updated_at")
        batch_op.drop_column("status_reason")
        batch_op.drop_column("breach_count")
        batch_op.drop_column("cost_per_call")
        batch_op.drop_column("data_access")
        batch_op.drop_column("permitted_actions")
        batch_op.drop_column("risk_category")
