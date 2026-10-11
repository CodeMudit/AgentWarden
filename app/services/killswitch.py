"""Global and per-agent kill switches."""

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


def suspend_agent(db: Session, agent: Agent, by: str) -> Agent:
    agent.status = "suspended"
    ledger.append(
        db,
        event_type="agent_suspended",
        actor_type="user",
        actor_id=by,
        subject_type="agent",
        subject_id=str(agent.id),
        payload={"name": agent.name},
    )
    db.flush()
    return agent


def resume_agent(db: Session, agent: Agent, by: str) -> Agent:
    agent.status = "active"
    ledger.append(
        db,
        event_type="agent_resumed",
        actor_type="user",
        actor_id=by,
        subject_type="agent",
        subject_id=str(agent.id),
        payload={"name": agent.name},
    )
    db.flush()
    return agent
