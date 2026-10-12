"""SQLAlchemy domain models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="reviewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    agents: Mapped[list[Agent]] = relationship("Agent", back_populates="owner")


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(Text, nullable=False, default="")
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    risk_tier: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    risk_category: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    permitted_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    data_access: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    cost_per_call: Mapped[float] = mapped_column(Float, nullable=False, default=0.01)
    breach_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status_updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    api_key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    owner: Mapped[User] = relationship("User", back_populates="agents")
    action_requests: Mapped[list[ActionRequest]] = relationship(
        "ActionRequest", back_populates="agent"
    )


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    rules: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


class ActionRequest(Base):
    __tablename__ = "action_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id"), nullable=False, index=True)
    tool: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    params: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    params_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    data_used: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    sensitivity: Mapped[str] = mapped_column(String(32), nullable=False, default="internal")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    matched_rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    decided_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_breach: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    breach_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    context: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    evaluation_trace: Mapped[dict[str, Any] | list | None] = mapped_column(JSON, nullable=True)

    agent: Mapped[Agent] = relationship("Agent", back_populates="action_requests")

    @property
    def decided_by(self) -> int | None:
        return self.decided_by_user_id

    @decided_by.setter
    def decided_by(self, value: int | None) -> None:
        self.decided_by_user_id = value


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    __table_args__ = (UniqueConstraint("seq", name="uq_ledger_seq"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    subject_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    subject_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)


class LedgerHead(Base):
    """Single-row lock target for concurrent-safe ledger appends."""

    __tablename__ = "ledger_head"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    last_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="0" * 64)


class SystemState(Base):
    """Global kill-switch / freeze state."""

    __tablename__ = "system_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    is_frozen: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    frozen_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    frozen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


class DecisionToken(Base):
    """Single-use decision token issued after ALLOW or human approval."""

    __tablename__ = "decision_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    action_id: Mapped[int] = mapped_column(ForeignKey("action_requests.id"), nullable=False, index=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id"), nullable=False, index=True)
    tool: Mapped[str] = mapped_column(String(128), nullable=False)
    params_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class WorkItem(Base):
    """Work item for human-versus-agent task allocation."""

    __tablename__ = "work_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    task_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    assignee_type: Mapped[str] = mapped_column(String(16), nullable=False)  # human | agent
    assignee_id: Mapped[str] = mapped_column(String(64), nullable=False)  # user id or agent name
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)  # queued, in_progress, completed, escalated, failed
    risk_category: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    action_request_id: Mapped[int | None] = mapped_column(ForeignKey("action_requests.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    action_request: Mapped[ActionRequest | None] = relationship("ActionRequest")


class ExceptionCase(Base):
    """Exception case created on agent failure, breach, or timeout."""

    __tablename__ = "exception_cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("agents.id"), nullable=True, index=True)
    action_request_id: Mapped[int | None] = mapped_column(ForeignKey("action_requests.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open", index=True)  # open, investigating, resolved
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="high")  # low, medium, high, critical
    assigned_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    agent: Mapped[Agent | None] = relationship("Agent")
    action_request: Mapped[ActionRequest | None] = relationship("ActionRequest")
    assigned_user: Mapped[User | None] = relationship("User")


class Incident(Base):
    """Incident for governance tracking and clear human accountability chain."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("agents.id"), nullable=True, index=True)
    action_request_id: Mapped[int | None] = mapped_column(ForeignKey("action_requests.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open", index=True)  # open, investigating, resolved
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="high")  # low, medium, high, critical
    created_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    assigned_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    agent: Mapped[Agent | None] = relationship("Agent")
    action_request: Mapped[ActionRequest | None] = relationship("ActionRequest")
    created_by: Mapped[User] = relationship("User", foreign_keys=[created_by_user_id])
    assigned_user: Mapped[User | None] = relationship("User", foreign_keys=[assigned_user_id])
