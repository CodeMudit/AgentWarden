"""Approve / reject with separation of duties."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger
from app.models import ActionRequest, Agent, User
from app.tokens import issue_token


class ApprovalError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def _get_action(db: Session, action_id: int) -> ActionRequest:
    ar = db.execute(select(ActionRequest).where(ActionRequest.id == action_id)).scalar_one_or_none()
    if ar is None:
        raise ApprovalError("not_found", "Action request not found")
    return ar


def approve(db: Session, action_id: int, user: User, reason: str) -> ActionRequest:
    if len(reason.strip()) < 10:
        raise ApprovalError("invalid_reason", "Reason must be at least 10 characters")

    ar = _get_action(db, action_id)
    if ar.status not in ("pending", "escalated"):
        raise ApprovalError("invalid_status", f"Cannot approve action in status {ar.status}")

    agent = db.execute(select(Agent).where(Agent.id == ar.agent_id)).scalar_one()

    # Separation of duties: owner cannot approve own agent's requests
    if agent.owner_user_id == user.id:
        raise ApprovalError(
            "separation_of_duties",
            "You own this agent, so a different reviewer must decide",
        )

    # Double decision blocked
    if ar.decided_by_user_id is not None:
        raise ApprovalError("already_decided", "This request has already been decided")

    now = datetime.now(UTC)
    ar.status = "approved"
    ar.decision = "allow"
    ar.decided_by_user_id = user.id
    ar.decided_at = now
    ar.decision_reason = reason.strip()

    ledger.append(
        db,
        event_type="approved",
        actor_type="user",
        actor_id=str(user.id),
        subject_type="action_request",
        subject_id=str(ar.id),
        payload={
            "reason": reason.strip(),
            "params_hash": ar.params_hash,
            "tool": ar.tool,
            "params": ar.params,
        },
        policy_version=ar.policy_version,
        ts=now,
    )
    if ar.params_hash:
        token = issue_token(
            db,
            action_id=ar.id,
            agent_id=ar.agent_id,
            tool=ar.tool,
            params_hash=ar.params_hash,
            policy_version=ar.policy_version,
        )
        ar._decision_token = token  # type: ignore[attr-defined]
    db.flush()
    return ar


def reject(db: Session, action_id: int, user: User, reason: str) -> ActionRequest:
    if len(reason.strip()) < 10:
        raise ApprovalError("invalid_reason", "Reason must be at least 10 characters")

    ar = _get_action(db, action_id)
    if ar.status not in ("pending", "escalated"):
        raise ApprovalError("invalid_status", f"Cannot reject action in status {ar.status}")

    agent = db.execute(select(Agent).where(Agent.id == ar.agent_id)).scalar_one()

    if agent.owner_user_id == user.id:
        raise ApprovalError(
            "separation_of_duties",
            "You own this agent, so a different reviewer must decide",
        )

    if ar.decided_by_user_id is not None:
        raise ApprovalError("already_decided", "This request has already been decided")

    now = datetime.now(UTC)
    ar.status = "rejected"
    ar.decision = "deny"
    ar.decided_by_user_id = user.id
    ar.decided_at = now
    ar.decision_reason = reason.strip()

    ledger.append(
        db,
        event_type="rejected",
        actor_type="user",
        actor_id=str(user.id),
        subject_type="action_request",
        subject_id=str(ar.id),
        payload={"reason": reason.strip()},
        policy_version=ar.policy_version,
        ts=now,
    )
    db.flush()
    return ar
