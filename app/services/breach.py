"""Deterministic policy breach detection and automatic agent pause."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger
from app.models import ActionRequest, Agent, ExceptionCase, Incident


def record_breach_and_pause(
    db: Session,
    agent: Agent,
    action_request: ActionRequest | None = None,
    reason: str = "Policy breach detected",
    triggering_rule_id: str | None = None,
) -> None:
    """Triggered on policy breach: auto-pauses agent, writes ledger events, creates incident."""
    now = datetime.now(UTC)

    # 1. Update Agent status
    agent.status = "paused"
    agent.breach_count = (agent.breach_count or 0) + 1
    agent.status_reason = reason
    agent.status_updated_at = now
    agent.status_updated_by = "breach_sentinel"

    # 2. Update ActionRequest if provided
    action_id_str = None
    if action_request is not None:
        action_request.is_breach = True
        action_request.breach_reason = reason
        action_id_str = str(action_request.id)

    # 3. Write policy_breach_detected event to ledger
    ledger.append(
        db,
        event_type="policy_breach_detected",
        actor_type="system",
        actor_id="breach_sentinel",
        subject_type="agent",
        subject_id=str(agent.id),
        payload={
            "agent_name": agent.name,
            "action_id": action_request.id if action_request else None,
            "reason": reason,
            "rule_id": triggering_rule_id,
        },
        policy_version=action_request.policy_version if action_request else None,
        ts=now,
    )

    # 4. Write agent_paused event to ledger
    ledger.append(
        db,
        event_type="agent_paused",
        actor_type="system",
        actor_id="breach_sentinel",
        subject_type="agent",
        subject_id=str(agent.id),
        payload={
            "agent_name": agent.name,
            "reason": reason,
            "action_id": action_request.id if action_request else None,
            "auto_triggered": True,
        },
        policy_version=action_request.policy_version if action_request else None,
        ts=now,
    )

    # 5. Create ExceptionCase for human owner
    exc = ExceptionCase(
        title=f"Policy breach on {agent.name}",
        agent_id=agent.id,
        action_request_id=action_request.id if action_request else None,
        status="open",
        severity="critical" if agent.risk_category in ("high", "critical") else "high",
        assigned_user_id=agent.owner_user_id,
        created_at=now,
    )
    db.add(exc)
    db.flush()

    ledger.append(
        db,
        event_type="exception_opened",
        actor_type="system",
        actor_id="breach_sentinel",
        subject_type="exception_case",
        subject_id=str(exc.id),
        payload={
            "agent_id": agent.id,
            "reason": reason,
            "assigned_user_id": agent.owner_user_id,
        },
        ts=now,
    )

    # 6. Open governance Incident
    inc = Incident(
        title=f"Policy breach: {agent.name} automatically paused",
        description=f"Agent '{agent.name}' (owned by User {agent.owner_user_id}) violated governance rules: {reason}. Status changed to PAUSED.",
        agent_id=agent.id,
        action_request_id=action_request.id if action_request else None,
        status="open",
        severity="critical" if agent.risk_category in ("high", "critical") else "high",
        created_by_user_id=agent.owner_user_id,
        assigned_user_id=agent.owner_user_id,
        created_at=now,
    )
    db.add(inc)
    db.flush()

    ledger.append(
        db,
        event_type="incident_opened",
        actor_type="system",
        actor_id="breach_sentinel",
        subject_type="incident",
        subject_id=str(inc.id),
        payload={
            "title": inc.title,
            "agent_id": agent.id,
            "action_id": action_request.id if action_request else None,
            "severity": inc.severity,
        },
        ts=now,
    )

    # 7. Flag any existing pending approvals from this agent
    pending_actions = list(
        db.execute(
            select(ActionRequest)
            .where(ActionRequest.agent_id == agent.id)
            .where(ActionRequest.status.in_(["pending", "escalated"]))
        )
        .scalars()
        .all()
    )
    for pa in pending_actions:
        pa.reason = (
            f"{pa.reason or ''} [FLAGGED: Agent paused due to policy breach: {reason}]".strip()
        )

    db.flush()
