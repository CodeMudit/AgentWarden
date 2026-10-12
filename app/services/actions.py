"""Action request / decide / complete workflow."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger
from app.config import get_settings
from app.ledger import canonical_json
from app.models import ActionRequest, Agent, ExceptionCase, Policy
from app.policy.engine import RequestContext, evaluate
from app.services.breach import record_breach_and_pause
from app.services.killswitch import is_system_frozen
from app.services.summaries import build_summary, maybe_reword_summary
from app.tokens import issue_token


def compute_params_hash(params: dict[str, Any] | None) -> str:
    """SHA-256 of canonical JSON params. Stable across key order."""
    return hashlib.sha256(canonical_json(params or {}).encode("utf-8")).hexdigest()


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
    data_used: list[str] | None = None,
    context: dict[str, Any] | None = None,
    sla_override_seconds: int | None = None,
) -> ActionRequest:
    now = datetime.now(UTC)
    settings = get_settings()
    data_used_list = data_used or []

    # 1. Kill switches & agent status first
    frozen, freeze_reason = is_system_frozen(db)
    eval_trace = None
    is_breach = False
    breach_reason = None
    triggering_rule = None

    if frozen:
        decision_effect = "deny"
        reason = freeze_reason or "System frozen"
        matched_rule = None
        policy_version = None
        status = "denied"
    elif agent.status in ("suspended", "paused"):
        decision_effect = "deny"
        reason = f"Agent is {agent.status}; all requests denied"
        matched_rule = None
        policy_version = None
        status = "denied"
    elif (
        getattr(agent, "permitted_actions", None)
        and tool not in agent.permitted_actions
    ):
        # Permitted action enforcement -> Policy breach
        decision_effect = "deny"
        status = "denied"
        is_breach = True
        reason = (
            f"Policy breach: tool '{tool}' is not in permitted_actions {agent.permitted_actions}"
        )
        breach_reason = reason
        matched_rule = "permitted_actions_whitelist"
        policy_version = None
    elif (
        getattr(agent, "data_access", None)
        and any(d not in agent.data_access for d in data_used_list)
    ):
        # Out-of-scope data access enforcement -> Policy breach
        unauthorized = [d for d in data_used_list if d not in agent.data_access]
        decision_effect = "deny"
        status = "denied"
        is_breach = True
        reason = (
            f"Policy breach: data scope {unauthorized} is not permitted for agent "
            f"(allowed: {agent.data_access})"
        )
        breach_reason = reason
        matched_rule = "data_access_scopes"
        policy_version = None
    elif agent.status == "restricted":
        # Restricted mode: agent only permitted for non-sensitive operations
        if sensitivity.lower() in ("confidential", "pii") or any(
            d.lower() in ("customer_pii", "financial_records") for d in data_used_list
        ):
            decision_effect = "deny"
            status = "denied"
            reason = f"Agent is restricted; sensitive action/data '{tool}' denied"
            matched_rule = "agent_restricted_mode"
            policy_version = None
        else:
            # Continue to evaluate policy under restricted constraints
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
                data_used=data_used_list,
                now=now,
            )
            decision = evaluate(policy_doc, ctx, history_counts=history, now=now)
            decision_effect = decision.effect
            reason = decision.reason
            matched_rule = decision.matched_rule_id
            eval_trace = decision.trace

            if decision_effect == "allow":
                status = "allowed"
            elif decision_effect == "deny":
                status = "denied"
            else:
                status = "pending"
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
            data_used=data_used_list,
            now=now,
        )
        decision = evaluate(policy_doc, ctx, history_counts=history, now=now)
        decision_effect = decision.effect
        reason = decision.reason
        matched_rule = decision.matched_rule_id
        eval_trace = decision.trace

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
    p_hash = compute_params_hash(params)

    ar = ActionRequest(
        agent_id=agent.id,
        tool=tool,
        params=params or {},
        params_hash=p_hash,
        data_used=data_used_list,
        sensitivity=sensitivity,
        status=status,
        decision=decision_effect,
        reason=reason,
        matched_rule_id=matched_rule,
        policy_version=policy_version,
        summary=summary,
        created_at=now,
        sla_deadline=sla_deadline,
        is_breach=is_breach,
        breach_reason=breach_reason,
        context=context,
        evaluation_trace=eval_trace,
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
        payload={
            "tool": tool,
            "params": params or {},
            "params_hash": p_hash,
            "sensitivity": sensitivity,
            "data_used": data_used_list,
        },
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
            "is_breach": is_breach,
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
            payload={
                "sla_deadline": sla_deadline.isoformat() if sla_deadline else None,
                "params_hash": p_hash,
                "tool": tool,
                "data_used": data_used_list,
            },
            policy_version=policy_version,
            ts=now,
        )

    # Automatic Pause on Policy Breach
    if is_breach:
        record_breach_and_pause(
            db,
            agent=agent,
            action_request=ar,
            reason=breach_reason or "Policy breach detected",
            triggering_rule_id=matched_rule,
        )

    if status == "allowed" and p_hash:
        token = issue_token(
            db,
            action_id=ar.id,
            agent_id=agent.id,
            tool=tool,
            params_hash=p_hash,
            policy_version=policy_version,
        )
        ar._decision_token = token  # type: ignore[attr-defined]

    db.flush()
    return ar


def complete_action(
    db: Session,
    agent: Agent,
    action_id: int,
    success: bool,
    result: dict[str, Any] | None = None,
    *,
    execution_params: dict[str, Any] | None = None,
) -> ActionRequest:
    """Mark an allowed/approved action as completed.

    If execution_params is provided, its hash must match the hash stored at
    request time; otherwise the completion is blocked (TOCTOU defence).
    """
    ar = db.execute(select(ActionRequest).where(ActionRequest.id == action_id)).scalar_one_or_none()
    if ar is None:
        raise LookupError("action not found")
    if ar.agent_id != agent.id:
        raise PermissionError("only the requesting agent may complete this action")
    if ar.status not in ("allowed", "approved"):
        raise ValueError(f"cannot complete action in status {ar.status}")
    if ar.status in ("completed", "failed"):
        raise ValueError("action already completed")

    if execution_params is not None and ar.params_hash:
        exec_hash = compute_params_hash(execution_params)
        if exec_hash != ar.params_hash:
            ledger.append(
                db,
                event_type="param_mismatch_blocked",
                actor_type="agent",
                actor_id=str(agent.id),
                subject_type="action_request",
                subject_id=str(ar.id),
                payload={
                    "expected_hash": ar.params_hash,
                    "got_hash": exec_hash,
                    "approved_params": ar.params,
                    "execution_params": execution_params,
                },
                policy_version=ar.policy_version,
            )
            # Persist the audit event even though completion is refused.
            db.commit()
            raise ValueError(
                "params_hash mismatch: execution params differ from approved params"
            )

    ar.status = "completed" if success else "failed"
    ar.result = result
    now = datetime.now(UTC)

    ledger.append(
        db,
        event_type="action_completed",
        actor_type="agent",
        actor_id=str(agent.id),
        subject_type="action_request",
        subject_id=str(ar.id),
        payload={
            "success": success,
            "result": result,
            "params_hash": ar.params_hash,
        },
        policy_version=ar.policy_version,
        ts=now,
    )

    # If action failed, automatically open an ExceptionCase for human investigator
    if not success:
        exc = ExceptionCase(
            title=f"Action failure: {agent.name} / {ar.tool}",
            agent_id=agent.id,
            action_request_id=ar.id,
            status="open",
            severity="medium",
            assigned_user_id=agent.owner_user_id,
            created_at=now,
        )
        db.add(exc)
        db.flush()
        ledger.append(
            db,
            event_type="exception_opened",
            actor_type="system",
            actor_id="execution_sentinel",
            subject_type="exception_case",
            subject_id=str(exc.id),
            payload={
                "agent_id": agent.id,
                "action_id": ar.id,
                "error": result.get("error") if result else None,
            },
            policy_version=ar.policy_version,
            ts=now,
        )

    db.flush()
    return ar
