"""Global and per-agent kill switches and governance state transitions."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger
from app.models import Agent, SystemState


def get_system_state(db: Session) -> SystemState:
    state = db.execute(select(SystemState).limit(1)).scalar_one_or_none()
    if state is None:
        state = SystemState(is_frozen=False)
        db.add(state)
        db.flush()
    return state


def is_system_frozen(db: Session) -> tuple[bool, str | None]:
    state = get_system_state(db)
    if state.is_frozen:
        who = state.frozen_by or "admin"
        return True, f"System frozen by {who}"
    return False, None


def freeze_system(db: Session, by: str, note: str | None = None) -> SystemState:
    state = get_system_state(db)
    state.is_frozen = True
    state.frozen_by = by
    state.frozen_at = datetime.now(UTC)
    state.note = note
    ledger.append(
        db,
        event_type="system_frozen",
        actor_type="user",
        actor_id=by,
        subject_type="system",
        subject_id="global",
        payload={"note": note},
    )
    db.flush()
    return state


def unfreeze_system(db: Session, by: str) -> SystemState:
    state = get_system_state(db)
    state.is_frozen = False
    state.frozen_by = None
    state.frozen_at = None
    state.note = None
    ledger.append(
        db,
        event_type="system_unfrozen",
        actor_type="user",
        actor_id=by,
        subject_type="system",
        subject_id="global",
        payload={},
    )
    db.flush()
    return state


def pause_agent(db: Session, agent: Agent, by: str, reason: str = "Manual pause") -> Agent:
    """Pause an agent: all requests will be denied."""
    now = datetime.now(UTC)
    agent.status = "paused"
    agent.status_reason = reason
    agent.status_updated_at = now
    agent.status_updated_by = by
    ledger.append(
        db,
        event_type="agent_paused",
        actor_type="user",
        actor_id=by,
        subject_type="agent",
        subject_id=str(agent.id),
        payload={"name": agent.name, "reason": reason},
        ts=now,
    )
    db.flush()
    return agent


def restrict_agent(db: Session, agent: Agent, by: str, reason: str = "Manual restriction") -> Agent:
    """Restrict an agent: reduces permissions to safe non-sensitive actions only."""
    now = datetime.now(UTC)
    agent.status = "restricted"
    agent.status_reason = reason
    agent.status_updated_at = now
    agent.status_updated_by = by
    ledger.append(
        db,
        event_type="agent_restricted",
        actor_type="user",
        actor_id=by,
        subject_type="agent",
        subject_id=str(agent.id),
        payload={"name": agent.name, "reason": reason},
        ts=now,
    )
    db.flush()
    return agent


def resume_agent(db: Session, agent: Agent, by: str, reason: str = "Manual resume") -> Agent:
    """Resume an agent: restores active status. Requires admin identity and written reason."""
    now = datetime.now(UTC)
    agent.status = "active"
    agent.status_reason = f"Resumed: {reason}"
    agent.status_updated_at = now
    agent.status_updated_by = by
    ledger.append(
        db,
        event_type="agent_resumed",
        actor_type="user",
        actor_id=by,
        subject_type="agent",
        subject_id=str(agent.id),
        payload={"name": agent.name, "reason": reason},
        ts=now,
    )
    db.flush()
    return agent


def suspend_agent(db: Session, agent: Agent, by: str, reason: str = "Manual suspend") -> Agent:
    """Backwards-compatible alias for pause_agent, writing agent_suspended and agent_paused."""
    now = datetime.now(UTC)
    agent.status = "suspended"
    agent.status_reason = reason
    agent.status_updated_at = now
    agent.status_updated_by = by
    ledger.append(
        db,
        event_type="agent_suspended",
        actor_type="user",
        actor_id=by,
        subject_type="agent",
        subject_id=str(agent.id),
        payload={"name": agent.name, "reason": reason},
        ts=now,
    )
    db.flush()
    return agent
