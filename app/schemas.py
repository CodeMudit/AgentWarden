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
    data_used: list[str] = Field(default_factory=list)
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
    decision_token: str | None = None  # issued on ALLOW; use to invoke tool


class ActionStatusOut(BaseModel):
    id: int
    agent_id: int
    tool: str
    params: dict[str, Any]
    params_hash: str | None = None
    data_used: list[str] = Field(default_factory=list)
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
    is_breach: bool = False
    breach_reason: str | None = None
    result: dict[str, Any] | None

    model_config = {"from_attributes": True}


class ActionCompleteIn(BaseModel):
    success: bool
    result: dict[str, Any] | None = None
    # Optional: if provided, must match the params hash approved at request time
    execution_params: dict[str, Any] | None = None


# --- Approvals ---


class ApprovalIn(BaseModel):
    reason: str = Field(..., min_length=10, max_length=2000)


# --- Agents ---


class AgentCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    purpose: str = ""
    owner_user_id: int
    risk_tier: str = "medium"
    risk_category: str | None = None
    permitted_actions: list[str] = Field(default_factory=list)
    data_access: list[str] = Field(default_factory=list)
    cost_per_call: float = 0.01

    @field_validator("risk_tier")
    @classmethod
    def tier_ok(cls, v: str) -> str:
        if v not in ("low", "medium", "high", "critical"):
            raise ValueError("risk_tier must be low|medium|high|critical")
        return v


class AgentStatusChangeIn(BaseModel):
    reason: str = Field(..., min_length=5, max_length=2000)


class AgentOut(BaseModel):
    id: int
    name: str
    purpose: str
    owner_user_id: int
    risk_tier: str
    risk_category: str = "medium"
    status: str
    permitted_actions: list[str] = Field(default_factory=list)
    data_access: list[str] = Field(default_factory=list)
    cost_per_call: float = 0.01
    breach_count: int = 0
    status_reason: str | None = None
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


# --- Users ---


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


# --- Tokens ---


class TokenVerifyIn(BaseModel):
    token: str
    tool: str | None = None
    params_hash: str | None = None
    agent_id: int | None = None


class TokenVerifyOut(BaseModel):
    valid: bool
    reason: str
    claims: dict[str, Any] | None = None


# --- Work Items ---


class WorkItemCreateIn(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    task_type: str = Field(..., min_length=2, max_length=64)
    risk_category: str = "medium"
    confidence_score: float | None = None
    preferred_agent_id: int | None = None
    preferred_user_id: int | None = None
    action_request_id: int | None = None
    notes: str | None = None


class WorkItemOut(BaseModel):
    id: int
    title: str
    task_type: str
    assignee_type: str
    assignee_id: str
    status: str
    risk_category: str
    confidence_score: float | None
    action_request_id: int | None
    created_at: datetime
    completed_at: datetime | None
    notes: str | None

    model_config = {"from_attributes": True}


# --- Exceptions ---


class ExceptionCreateIn(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    agent_id: int | None = None
    action_request_id: int | None = None
    severity: str = "high"
    assigned_user_id: int | None = None
    initial_note: str | None = None


class ExceptionResolveIn(BaseModel):
    resolution_note: str = Field(..., min_length=10, max_length=2000)


class ExceptionOut(BaseModel):
    id: int
    title: str
    agent_id: int | None
    action_request_id: int | None
    status: str
    severity: str
    assigned_user_id: int | None
    resolution_note: str | None
    created_at: datetime
    resolved_at: datetime | None

    model_config = {"from_attributes": True}


# --- Incidents ---


class IncidentCreateIn(BaseModel):
    title: str = Field(..., min_length=5, max_length=255)
    description: str = Field(..., min_length=10, max_length=5000)
    agent_id: int | None = None
    action_request_id: int | None = None
    severity: str = "high"
    assigned_user_id: int | None = None


class IncidentResolveIn(BaseModel):
    resolution_notes: str = Field(..., min_length=10, max_length=2000)


class IncidentOut(BaseModel):
    id: int
    title: str
    description: str
    agent_id: int | None
    action_request_id: int | None
    status: str
    severity: str
    created_by_user_id: int
    assigned_user_id: int | None
    resolution_notes: str | None
    created_at: datetime
    resolved_at: datetime | None

    model_config = {"from_attributes": True}
