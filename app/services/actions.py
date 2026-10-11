"""Action request / decide / complete workflow."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger
from app.config import get_settings
from app.models import ActionRequest, Agent, Policy
from app.policy.engine import RequestContext, evaluate
from app.services.killswitch import is_system_frozen
from app.services.summaries import build_summary, maybe_reword_summary


def _active_policy(db: Session) -> Policy | None:
    return db.execute(select(Policy).where(Policy.is_active.is_(True))).scalar_one_or_none()


def _rate_history_counts(
    db: Session, agent_name: str, tool: str, window_seconds: int, now: datetime
) -> dict[str, int]:
    """Count recent requests for rate_limit conditions."""
    since = now - timedelta(seconds=window_seconds)
    q = (
        select(ActionRequest)
        .join(Agent, ActionRequest.agent_id == Agent.id)
        .where(Agent.name == agent_name)
        .where(ActionRequest.tool == tool)
        .where(ActionRequest.created_at >= since)
    )
    rows = list(db.execute(q).scalars().all())
    key = f"{agent_name}:{tool}:{window_seconds}"
    return {key: len(rows)}


def _collect_rate_counts(
    db: Session, agent_name: str, tool: str, policy_rules: dict, now: datetime
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rule in policy_rules.get("rules") or []:
        for cond in rule.get("conditions") or []:
            if cond.get("type") == "rate_limit":
                conf = cond.get("value") or {}
                window = int(conf.get("window_seconds", 60))
                counts.update(_rate_history_counts(db, agent_name, tool, window, now))
    return counts


def request_action(
    db: Session,
    agent: Agent,
    tool: str,
    params: dict[str, Any],
    sensitivity: str,
    context: dict[str, Any] | None = None,
    sla_override_seconds: int | None = None,
) -> ActionRequest:
    now = datetime.now(UTC)
    settings = get_settings()

    # Kill switches first
    frozen, freeze_reason = is_system_frozen(db)
    if frozen:
        decision_effect = "deny"
        reason = freeze_reason or "System frozen"
        matched_rule = None
        policy_version = None
        status = "denied"
    elif agent.status == "suspended":
        decision_effect = "deny"
        reason = "Agent suspended"
        matched_rule = None
        policy_version = None
        status = "denied"
    else:
        policy_row = _active_policy(db)
        if policy_row is None:
            policy_doc = {"default_effect": "deny", "rules": []}
            policy_version = None
        else:
            policy_doc = policy_row.rules
            policy_version = policy_row.version

        history = _collect_rate_counts(db, agent.name, tool, policy_doc, now)
        ctx = RequestContext(
            agent_name=agent.name,
            tool=tool,
            params=params or {},
            sensitivity=sensitivity,
            now=now,
        )
        decision = evaluate(policy_doc, ctx, history_counts=history, now=now)
        decision_effect = decision.effect
        reason = decision.reason
        matched_rule = decision.matched_rule_id

        if decision_effect == "allow":
            status = "allowed"
        elif decision_effect == "deny":
            status = "denied"
        else:
            status = "pending"

    sla_secs = (
        sla_override_seconds if sla_override_seconds is not None else settings.approval_sla_seconds
    )
    sla_deadline = None
    if status == "pending":
        sla_deadline = now + timedelta(seconds=sla_secs)

    summary = maybe_reword_summary(build_summary(tool, params or {}, sensitivity, agent.name))

    ar = ActionRequest(
        agent_id=agent.id,
        tool=tool,
        params=params or {},
        sensitivity=sensitivity,
        status=status,
        decision=decision_effect,
        reason=reason,
        matched_rule_id=matched_rule,
        policy_version=policy_version,
        summary=summary,
        created_at=now,
        sla_deadline=sla_deadline,
        context=context,
    )
    db.add(ar)
    db.flush()

    ledger.append(
        db,
        event_type="action_requested",
        actor_type="agent",
        actor_id=str(agent.id),
        subject_type="action_request",
        subject_id=str(ar.id),
        payload={"tool": tool, "params": params or {}, "sensitivity": sensitivity},
        policy_version=policy_version,
        ts=now,
    )
    ledger.append(
        db,
        event_type="decision_made",
        actor_type="system",
        actor_id="policy_engine",
        subject_type="action_request",
        subject_id=str(ar.id),
        payload={
            "decision": decision_effect,
            "reason": reason,
            "matched_rule_id": matched_rule,
        },
        policy_version=policy_version,
        ts=now,
    )
    if status == "pending":
        ledger.append(
            db,
            event_type="approval_requested",
            actor_type="system",
            actor_id="policy_engine",
            subject_type="action_request",
            subject_id=str(ar.id),
            payload={"sla_deadline": sla_deadline.isoformat() if sla_deadline else None},
            policy_version=policy_version,
            ts=now,
        )

    db.flush()
    return ar


def complete_action(
    db: Session,
    agent: Agent,
    action_id: int,
    success: bool,
    result: dict[str, Any] | None = None,
) -> ActionRequest:
    ar = db.execute(select(ActionRequest).where(ActionRequest.id == action_id)).scalar_one_or_none()
    if ar is None:
        raise LookupError("action not found")
    if ar.agent_id != agent.id:
        raise PermissionError("only the requesting agent may complete this action")
    if ar.status not in ("allowed", "approved"):
        raise ValueError(f"cannot complete action in status {ar.status}")
    if ar.status in ("completed", "failed"):
        raise ValueError("action already completed")

    ar.status = "completed" if success else "failed"
    ar.result = result
    ledger.append(
        db,
        event_type="action_completed",
        actor_type="agent",
        actor_id=str(agent.id),
        subject_type="action_request",
        subject_id=str(ar.id),
        payload={"success": success, "result": result},
        policy_version=ar.policy_version,
    )
    db.flush()
    return ar
