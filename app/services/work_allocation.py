"""Deterministic human-versus-agent work allocation and routing engine."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger
from app.models import ActionRequest, Agent, User, WorkItem


def route_work_item(
    db: Session,
    title: str,
    task_type: str,
    risk_category: str = "medium",
    confidence_score: float | None = None,
    preferred_agent_id: int | None = None,
    preferred_user_id: int | None = None,
    action_request_id: int | None = None,
    notes: str | None = None,
) -> WorkItem:
    """Deterministically route a task to human or agent based on governance rules.

    Rules:
    - High or critical risk -> Human reviewer.
    - Low confidence (< 0.85) -> Human reviewer.
    - Routine (low/medium risk, high confidence) -> AI agent.
    """
    now = datetime.now(UTC)

    # Determine assignee
    is_high_risk = risk_category.lower() in ("high", "critical")
    is_low_confidence = confidence_score is not None and confidence_score < 0.85

    if is_high_risk or is_low_confidence:
        assignee_type = "human"
        routing_reason = "Routed to human: " + (
            f"high risk tier ({risk_category})"
            if is_high_risk
            else f"low confidence score ({confidence_score:.2f})"
        )
        if preferred_user_id:
            assignee_id = str(preferred_user_id)
        else:
            first_reviewer = db.execute(
                select(User).where(User.role.in_(["reviewer", "admin"])).limit(1)
            ).scalar_one_or_none()
            assignee_id = str(first_reviewer.id) if first_reviewer else "1"
    else:
        assignee_type = "agent"
        routing_reason = f"Routed to agent: routine task ({risk_category} risk, confidence {confidence_score or 0.95:.2f})"
        if preferred_agent_id:
            agent = db.execute(select(Agent).where(Agent.id == preferred_agent_id)).scalar_one_or_none()
            assignee_id = agent.name if agent else str(preferred_agent_id)
        else:
            first_agent = db.execute(select(Agent).where(Agent.status == "active").limit(1)).scalar_one_or_none()
            assignee_id = first_agent.name if first_agent else "agent"

    full_notes = f"{routing_reason}. {notes or ''}".strip()

    item = WorkItem(
        title=title,
        task_type=task_type,
        assignee_type=assignee_type,
        assignee_id=assignee_id,
        status="in_progress" if assignee_type == "agent" else "queued",
        risk_category=risk_category,
        confidence_score=confidence_score,
        action_request_id=action_request_id,
        notes=full_notes,
        created_at=now,
    )
    db.add(item)
    db.flush()

    ledger.append(
        db,
        event_type="work_item_created",
        actor_type="system",
        actor_id="router",
        subject_type="work_item",
        subject_id=str(item.id),
        payload={
            "title": title,
            "task_type": task_type,
            "risk_category": risk_category,
            "confidence_score": confidence_score,
        },
        ts=now,
    )

    ledger.append(
        db,
        event_type="work_item_routed",
        actor_type="system",
        actor_id="router",
        subject_type="work_item",
        subject_id=str(item.id),
        payload={
            "assignee_type": assignee_type,
            "assignee_id": assignee_id,
            "reason": routing_reason,
        },
        ts=now,
    )

    db.flush()
    return item


def complete_work_item(
    db: Session,
    item_id: int,
    status: str = "completed",
    resolution_notes: str | None = None,
) -> WorkItem:
    """Mark a work item completed or escalated with an append-only ledger record."""
    item = db.execute(select(WorkItem).where(WorkItem.id == item_id)).scalar_one_or_none()
    if item is None:
        raise LookupError("Work item not found")

    now = datetime.now(UTC)
    item.status = status
    item.completed_at = now
    if resolution_notes:
        item.notes = f"{item.notes or ''}\nResolution: {resolution_notes}".strip()

    ledger.append(
        db,
        event_type="work_item_completed",
        actor_type="system",
        actor_id=item.assignee_id,
        subject_type="work_item",
        subject_id=str(item.id),
        payload={"status": status, "resolution": resolution_notes},
        ts=now,
    )
    db.flush()
    return item


def get_allocation_metrics(db: Session) -> dict[str, Any]:
    """Calculate real work allocation metrics derived from work_items in DB."""
    items = list(db.execute(select(WorkItem)).scalars().all())
    total = len(items)
    human_count = sum(1 for i in items if i.assignee_type == "human")
    agent_count = sum(1 for i in items if i.assignee_type == "agent")

    human_pct = round((human_count / total * 100), 1) if total > 0 else 0.0
    agent_pct = round((agent_count / total * 100), 1) if total > 0 else 0.0

    by_risk = {
        "low": {"human": 0, "agent": 0},
        "medium": {"human": 0, "agent": 0},
        "high": {"human": 0, "agent": 0},
        "critical": {"human": 0, "agent": 0},
    }
    for i in items:
        rc = i.risk_category.lower() if i.risk_category else "medium"
        if rc in by_risk:
            by_risk[rc][i.assignee_type] = by_risk[rc].get(i.assignee_type, 0) + 1

    handoffs = sum(
        1 for i in items if i.status == "escalated" or (i.notes and "Handoff" in i.notes)
    )

    return {
        "total": total,
        "human_count": human_count,
        "agent_count": agent_count,
        "human_pct": human_pct,
        "agent_pct": agent_pct,
        "human_allocated_pct": human_pct,
        "agent_allocated_pct": agent_pct,
        "handoffs": handoffs,
        "by_risk": by_risk,
    }
