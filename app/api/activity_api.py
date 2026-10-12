"""Unified activity trail JSON API with multidimensional filters and full audit links."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import ActionRequest, Agent, LedgerEntry, User
from app.security import require_session_user

router = APIRouter(prefix="/activity", tags=["activity"])


def redact_params(params: dict[str, Any], sensitivity: str = "internal") -> dict[str, Any]:
    """Redact sensitive credentials, tokens, or PII params."""
    redacted = dict(params or {})
    sensitive_keys = {"password", "secret", "token", "ssn", "card", "cvv", "key", "api_key"}
    for k, v in list(redacted.items()):
        if any(sk in k.lower() for sk in sensitive_keys):
            redacted[k] = "[REDACTED]"
        elif sensitivity.lower() in ("confidential", "pii") and k in ("email_body", "message", "query"):
            if isinstance(v, str) and len(v) > 20:
                redacted[k] = v[:15] + "… [REDACTED]"
    return redacted


@router.get("")
def list_activity(
    agent_id: int | None = Query(None),
    decision: str | None = Query(None),
    risk_category: str | None = Query(None),
    outcome: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: User = Depends(require_session_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Unified activity trail with filters: agent, decision, risk tier, outcome, date range."""
    q = (
        select(ActionRequest, Agent, User)
        .join(Agent, ActionRequest.agent_id == Agent.id)
        .join(User, Agent.owner_user_id == User.id)
        .order_by(ActionRequest.created_at.desc())
    )

    if agent_id:
        q = q.where(ActionRequest.agent_id == agent_id)
    if decision:
        q = q.where(ActionRequest.decision == decision)
    if risk_category:
        q = q.where(Agent.risk_category == risk_category)
    if outcome:
        q = q.where(ActionRequest.status == outcome)
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from)
            q = q.where(ActionRequest.created_at >= dt_from)
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
            q = q.where(ActionRequest.created_at <= dt_to)
        except ValueError:
            pass

    q = q.limit(limit).offset(offset)
    rows = db.execute(q).all()

    # Pre-fetch users for approvers
    approver_ids = {ar.decided_by_user_id for ar, _, _ in rows if ar.decided_by_user_id}
    approvers = {}
    if approver_ids:
        approver_rows = db.execute(select(User).where(User.id.in_(approver_ids))).scalars().all()
        approvers = {u.id: u for u in approver_rows}

    # Pre-fetch primary ledger entries for these actions
    action_ids = [str(ar.id) for ar, _, _ in rows]
    ledger_entries = {}
    if action_ids:
        entries = (
            db.execute(
                select(LedgerEntry)
                .where(LedgerEntry.subject_type == "action_request")
                .where(LedgerEntry.subject_id.in_(action_ids))
                .where(LedgerEntry.event_type.in_(["decision_made", "approved", "rejected", "action_completed"]))
            )
            .scalars()
            .all()
        )
        for le in entries:
            ledger_entries[le.subject_id] = le

    items = []
    for ar, ag, owner in rows:
        appr = approvers.get(ar.decided_by_user_id) if ar.decided_by_user_id else None
        le = ledger_entries.get(str(ar.id))
        items.append(
            {
                "id": ar.id,
                "agent": {
                    "id": ag.id,
                    "name": ag.name,
                    "risk_category": getattr(ag, "risk_category", ag.risk_tier),
                    "status": ag.status,
                    "owner_name": owner.name,
                    "owner_email": owner.email,
                },
                "tool": ar.tool,
                "params": redact_params(ar.params, ar.sensitivity),
                "params_hash": ar.params_hash,
                "data_used": getattr(ar, "data_used", []),
                "sensitivity": ar.sensitivity,
                "matched_rule_id": ar.matched_rule_id,
                "policy_version": ar.policy_version,
                "decision": ar.decision,
                "reason": ar.reason,
                "status": ar.status,
                "approver": {
                    "id": appr.id,
                    "name": appr.name,
                    "email": appr.email,
                }
                if appr
                else None,
                "decision_reason": ar.decision_reason,
                "decided_at": ar.decided_at.isoformat() if ar.decided_at else None,
                "is_breach": getattr(ar, "is_breach", False),
                "breach_reason": getattr(ar, "breach_reason", None),
                "created_at": ar.created_at.isoformat() if ar.created_at else None,
                "result": ar.result,
                "ledger_seq": le.seq if le else None,
                "ledger_hash": le.hash if le else None,
            }
        )

    return {
        "count": len(items),
        "limit": limit,
        "offset": offset,
        "items": items,
    }


@router.get("/{action_id}/chain")
def get_action_chain(
    action_id: int,
    user: User = Depends(require_session_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve the complete hash-chained action history and policy match."""
    ar = db.execute(select(ActionRequest).where(ActionRequest.id == action_id)).scalar_one_or_none()
    if ar is None:
        return {"error": "Action not found"}

    ag = db.execute(select(Agent).where(Agent.id == ar.agent_id)).scalar_one_or_none()
    owner = (
        db.execute(select(User).where(User.id == ag.owner_user_id)).scalar_one_or_none()
        if ag
        else None
    )
    approver = (
        db.execute(select(User).where(User.id == ar.decided_by_user_id)).scalar_one_or_none()
        if ar.decided_by_user_id
        else None
    )

    entries = list(
        db.execute(
            select(LedgerEntry)
            .where(LedgerEntry.subject_type == "action_request")
            .where(LedgerEntry.subject_id == str(ar.id))
            .order_by(LedgerEntry.seq.asc())
        )
        .scalars()
        .all()
    )

    return {
        "action": {
            "id": ar.id,
            "tool": ar.tool,
            "params": redact_params(ar.params, ar.sensitivity),
            "params_hash": ar.params_hash,
            "data_used": getattr(ar, "data_used", []),
            "sensitivity": ar.sensitivity,
            "decision": ar.decision,
            "reason": ar.reason,
            "status": ar.status,
            "matched_rule_id": ar.matched_rule_id,
            "policy_version": ar.policy_version,
            "is_breach": getattr(ar, "is_breach", False),
            "breach_reason": getattr(ar, "breach_reason", None),
            "created_at": ar.created_at.isoformat() if ar.created_at else None,
            "decided_at": ar.decided_at.isoformat() if ar.decided_at else None,
            "decision_reason": ar.decision_reason,
            "result": ar.result,
        },
        "agent": {
            "id": ag.id if ag else None,
            "name": ag.name if ag else None,
            "purpose": ag.purpose if ag else None,
            "risk_category": getattr(ag, "risk_category", ag.risk_tier) if ag else None,
            "status": ag.status if ag else None,
            "owner": {"name": owner.name, "email": owner.email} if owner else None,
        },
        "approver": {
            "id": approver.id,
            "name": approver.name,
            "email": approver.email,
        }
        if approver
        else None,
        "ledger_trail": [
            {
                "seq": e.seq,
                "event_type": e.event_type,
                "actor_type": e.actor_type,
                "actor_id": e.actor_id,
                "hash": e.hash,
                "prev_hash": e.prev_hash,
                "ts": e.ts.isoformat() if e.ts else None,
                "payload": e.payload,
            }
            for e in entries
        ],
    }
