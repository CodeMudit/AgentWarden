"""Pydantic request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail


# --- Actions ---


class ActionRequestIn(BaseModel):
    tool: str = Field(..., min_length=1, max_length=128)
    params: dict[str, Any] = Field(default_factory=dict)
    sensitivity: str = Field(default="internal")
    context: dict[str, Any] | None = None

    @field_validator("sensitivity")
    @classmethod
    def sens_ok(cls, v: str) -> str:
        allowed = {"public", "internal", "confidential", "pii"}
        if v.lower() not in allowed:
            raise ValueError(f"sensitivity must be one of {sorted(allowed)}")
        return v.lower()


class ActionDecisionOut(BaseModel):
    id: int
    decision: str
    reason: str | None = None
    matched_rule_id: str | None = None
    policy_version: int | None = None
    status: str | None = None
    poll_url: str | None = None


class ActionStatusOut(BaseModel):
    id: int
    agent_id: int
    tool: str
    params: dict[str, Any]
    sensitivity: str
    status: str
    decision: str | None
    reason: str | None
    matched_rule_id: str | None
    policy_version: int | None
    summary: str | None
    created_at: datetime
    decided_at: datetime | None
    decision_reason: str | None
    escalated_at: datetime | None
    sla_deadline: datetime | None
    result: dict[str, Any] | None

    model_config = {"from_attributes": True}


class ActionCompleteIn(BaseModel):
    success: bool
    result: dict[str, Any] | None = None


# --- Approvals ---


class ApprovalIn(BaseModel):
    reason: str = Field(..., min_length=10, max_length=2000)


# --- Agents ---


class AgentCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    purpose: str = ""
    owner_user_id: int
    risk_tier: str = "medium"

    @field_validator("risk_tier")
    @classmethod
    def tier_ok(cls, v: str) -> str:
        if v not in ("low", "medium", "high"):
            raise ValueError("risk_tier must be low|medium|high")
        return v


class AgentOut(BaseModel):
    id: int
    name: str
    purpose: str
    owner_user_id: int
    risk_tier: str
    status: str
    api_key_prefix: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AgentCreateOut(AgentOut):
    api_key: str  # shown once


# --- Policies ---


class PolicyCreateIn(BaseModel):
    rules: dict[str, Any]
    note: str | None = None


class PolicyOut(BaseModel):
    id: int
    version: int
    rules: dict[str, Any]
    is_active: bool
    created_by: int | None
    created_at: datetime
    note: str | None

    model_config = {"from_attributes": True}


class PolicySimulateIn(BaseModel):
    rules: dict[str, Any]
    last_n: int | None = 50
    since: datetime | None = None
    until: datetime | None = None


class SimulateChangedItem(BaseModel):
    action_id: int
    tool: str
    agent_name: str
    old_decision: str | None
    new_decision: str
    old_rule: str | None
    new_rule: str | None


class PolicySimulateOut(BaseModel):
    total: int
    unchanged: int
    newly_allowed: int
    newly_denied: int
    newly_require_approval: int
    changed: list[SimulateChangedItem]


# --- Ledger ---


class LedgerEntryOut(BaseModel):
    seq: int
    ts: datetime
    event_type: str
    actor_type: str
    actor_id: str | None
    subject_type: str | None
    subject_id: str | None
    payload: dict[str, Any]
    policy_version: int | None
    prev_hash: str
    hash: str

    model_config = {"from_attributes": True}


class CheckpointIn(BaseModel):
    seq: int
    hash: str
    ts: str
    hmac: str


# --- System ---


class FreezeIn(BaseModel):
    note: str | None = None


# --- Users (minimal for Phase 1 tests) ---


class UserCreateIn(BaseModel):
    email: str
    name: str
    password: str
    role: str = "reviewer"


class UserOut(BaseModel):
    id: int
    email: str
    name: str
    role: str
    is_active: bool

    model_config = {"from_attributes": True}
