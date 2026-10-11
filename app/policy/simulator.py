"""Replay stored requests against a draft policy and diff decisions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ActionRequest, Agent
from app.policy.engine import RequestContext, evaluate


def simulate(
    db: Session,
    draft_policy: dict[str, Any],
    last_n: int | None = 50,
    since: datetime | None = None,
    until: datetime | None = None,
) -> dict[str, Any]:
    q = select(ActionRequest).join(Agent, ActionRequest.agent_id == Agent.id)
    if since is not None:
        q = q.where(ActionRequest.created_at >= since)
    if until is not None:
        q = q.where(ActionRequest.created_at <= until)
    q = q.order_by(ActionRequest.created_at.desc())
    if last_n is not None and since is None:
        q = q.limit(last_n)

    rows = list(db.execute(q).scalars().all())
    # Replay in chronological order for rate limits
    rows_chrono = list(reversed(rows))

    # Build agent name map
    agent_ids = {r.agent_id for r in rows_chrono}
    agents = {
        a.id: a for a in db.execute(select(Agent).where(Agent.id.in_(agent_ids))).scalars().all()
    }

    unchanged = 0
    newly_allowed = 0
    newly_denied = 0
    newly_require_approval = 0
    changed: list[dict[str, Any]] = []

    # Replay history for rate_limit: accumulate counts as we go
    # Store timestamps of replayed requests for window counting
    history_events: list[tuple[str, str, datetime]] = []  # agent, tool, ts

    for ar in rows_chrono:
        agent = agents.get(ar.agent_id)
        agent_name = agent.name if agent else f"agent-{ar.agent_id}"
        now = ar.created_at
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)

        # Build rate counts from replayed history
        counts: dict[str, int] = {}
        for rule in draft_policy.get("rules") or []:
            for cond in rule.get("conditions") or []:
                if cond.get("type") == "rate_limit":
                    conf = cond.get("value") or {}
                    window = int(conf.get("window_seconds", 60))
                    key = f"{agent_name}:{ar.tool}:{window}"
                    cutoff = now - timedelta(seconds=window)
                    c = sum(
                        1
                        for an, tl, ts in history_events
                        if an == agent_name and tl == ar.tool and ts >= cutoff
                    )
                    counts[key] = c

        ctx = RequestContext(
            agent_name=agent_name,
            tool=ar.tool,
            params=ar.params or {},
            sensitivity=ar.sensitivity,
            now=now,
        )
        new_dec = evaluate(draft_policy, ctx, history_counts=counts, now=now)
        old_dec = ar.decision
        old_rule = ar.matched_rule_id

        history_events.append((agent_name, ar.tool, now))

        if old_dec == new_dec.effect and old_rule == new_dec.matched_rule_id:
            unchanged += 1
        else:
            if new_dec.effect == "allow" and old_dec != "allow":
                newly_allowed += 1
            elif new_dec.effect == "deny" and old_dec != "deny":
                newly_denied += 1
            elif new_dec.effect == "require_approval" and old_dec != "require_approval":
                newly_require_approval += 1
            else:
                # decision same but rule changed, or other transitions
                if new_dec.effect == "allow":
                    newly_allowed += 1
                elif new_dec.effect == "deny":
                    newly_denied += 1
                else:
                    newly_require_approval += 1
            changed.append(
                {
                    "action_id": ar.id,
                    "tool": ar.tool,
                    "agent_name": agent_name,
                    "old_decision": old_dec,
                    "new_decision": new_dec.effect,
                    "old_rule": old_rule,
                    "new_rule": new_dec.matched_rule_id,
                }
            )

    return {
        "total": len(rows_chrono),
        "unchanged": unchanged,
        "newly_allowed": newly_allowed,
        "newly_denied": newly_denied,
        "newly_require_approval": newly_require_approval,
        "changed": changed,
    }
