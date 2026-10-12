"""Incident management and end-to-end human accountability chain tracing."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger
from app.models import ActionRequest, Agent, Incident, LedgerEntry, Policy, User


class IncidentError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def open_incident(
    db: Session,
    title: str,
    description: str,
    creator_user: User | None = None,
    created_by_user_id: int | None = None,
    agent_id: int | None = None,
    action_request_id: int | None = None,
    severity: str = "high",
    assigned_user_id: int | None = None,
) -> Incident:
    if len(title.strip()) < 5:
        raise IncidentError("invalid_title", "Title must be at least 5 characters")
    if len(description.strip()) < 10:
        raise IncidentError("invalid_description", "Description must be at least 10 characters")

    now = datetime.now(UTC)
    uid = creator_user.id if creator_user else created_by_user_id
    if uid is None:
        first_admin = db.execute(select(User).where(User.role == "admin").limit(1)).scalar_one_or_none()
        uid = first_admin.id if first_admin else 1
    uname = creator_user.name if creator_user else None
    if not uname:
        u_row = db.execute(select(User).where(User.id == uid)).scalar_one_or_none()
        uname = u_row.name if u_row else "System Sentinel"

    inc = Incident(
        title=title.strip(),
        description=description.strip(),
        agent_id=agent_id,
        action_request_id=action_request_id,
        status="open",
        severity=severity,
        created_by_user_id=uid,
        assigned_user_id=assigned_user_id or uid,
        created_at=now,
    )
    db.add(inc)
    db.flush()

    ledger.append(
        db,
        event_type="incident_opened",
        actor_type="user",
        actor_id=str(uid),
        subject_type="incident",
        subject_id=str(inc.id),
        payload={
            "title": inc.title,
            "agent_id": agent_id,
            "action_id": action_request_id,
            "severity": severity,
            "created_by": uname,
        },
        ts=now,
    )
    db.flush()
    return inc


def resolve_incident(
    db: Session,
    incident_id: int,
    user: User | int,
    resolution_notes: str,
) -> Incident:
    if len(resolution_notes.strip()) < 10:
        raise IncidentError("invalid_notes", "Resolution notes must be at least 10 characters")

    inc = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
    if inc is None:
        raise IncidentError("not_found", "Incident not found")
    if inc.status == "resolved":
        raise IncidentError("already_resolved", "Incident is already resolved")

    now = datetime.now(UTC)
    uid = user.id if isinstance(user, User) else user
    uname = user.name if isinstance(user, User) else None
    if not uname:
        u_row = db.execute(select(User).where(User.id == uid)).scalar_one_or_none()
        uname = u_row.name if u_row else str(uid)

    inc.status = "resolved"
    inc.resolution_notes = resolution_notes.strip()
    inc.resolved_at = now
    inc.assigned_user_id = uid

    ledger.append(
        db,
        event_type="incident_resolved",
        actor_type="user",
        actor_id=str(uid),
        subject_type="incident",
        subject_id=str(inc.id),
        payload={
            "resolution_notes": resolution_notes.strip(),
            "resolved_by": uname,
        },
        ts=now,
    )
    db.flush()
    return inc


def get_accountability_chain(db: Session, incident: Incident | int) -> dict[str, Any] | None:
    """Build the end-to-end accountability chain for an incident.

    Traces:
    1. AI Agent: name, purpose, risk tier, status
    2. Accountable Human Owner: user name, email, role
    3. Action Request: tool, parameters, data used, timestamp
    4. Policy Rule: rule ID, description, priority, conditions
    5. Human Approver (if any): name, email, decision, written reason
    6. Outcome: success/failure, result, params hash
    7. Append-only Ledger: exact hash-chained sequence entries
    8. Human Incident Resolution: resolver, notes, timestamp
    """
    if isinstance(incident, int):
        inc_obj = db.execute(select(Incident).where(Incident.id == incident)).scalar_one_or_none()
        if inc_obj is None:
            return None
        incident = inc_obj

    agent = None
    owner = None
    if incident.agent_id:
        agent = db.execute(select(Agent).where(Agent.id == incident.agent_id)).scalar_one_or_none()
        if agent:
            owner = db.execute(select(User).where(User.id == agent.owner_user_id)).scalar_one_or_none()

    ar = None
    approver = None
    rule_info = None
    ledger_entries = []

    if incident.action_request_id:
        ar = db.execute(select(ActionRequest).where(ActionRequest.id == incident.action_request_id)).scalar_one_or_none()
        if ar:
            if not agent:
                agent = db.execute(select(Agent).where(Agent.id == ar.agent_id)).scalar_one_or_none()
                if agent:
                    owner = db.execute(select(User).where(User.id == agent.owner_user_id)).scalar_one_or_none()
            if ar.decided_by_user_id:
                approver = db.execute(select(User).where(User.id == ar.decided_by_user_id)).scalar_one_or_none()

            # Find matching rule in policy
            if ar.policy_version:
                p = db.execute(select(Policy).where(Policy.version == ar.policy_version)).scalar_one_or_none()
                if p and isinstance(p.rules, dict):
                    for r in p.rules.get("rules", []):
                        if r.get("id") == ar.matched_rule_id:
                            rule_info = r
                            break

            # Find all ledger entries related to this action request
            q_ledger = (
                select(LedgerEntry)
                .where(
                    (LedgerEntry.subject_type == "action_request") & (LedgerEntry.subject_id == str(ar.id))
                    | (LedgerEntry.subject_type == "incident") & (LedgerEntry.subject_id == str(incident.id))
                )
                .order_by(LedgerEntry.seq.asc())
            )
            ledger_entries = list(db.execute(q_ledger).scalars().all())

    # If no action request entries found, find entries for the incident and agent
    if not ledger_entries and incident.id:
        q_ledger = (
            select(LedgerEntry)
            .where(
                (LedgerEntry.subject_type == "incident") & (LedgerEntry.subject_id == str(incident.id))
                | (agent and (LedgerEntry.subject_type == "agent") & (LedgerEntry.subject_id == str(agent.id)))
            )
            .order_by(LedgerEntry.seq.asc())
            .limit(20)
        )
        ledger_entries = list(db.execute(q_ledger).scalars().all())

    creator = db.execute(select(User).where(User.id == incident.created_by_user_id)).scalar_one_or_none()
    assigned = (
        db.execute(select(User).where(User.id == incident.assigned_user_id)).scalar_one_or_none()
        if incident.assigned_user_id
        else None
    )

    return {
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "created_at": incident.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if incident.created_at else None,
            "resolved_at": incident.resolved_at.strftime("%Y-%m-%d %H:%M:%S UTC") if incident.resolved_at else None,
            "resolution_notes": incident.resolution_notes,
            "creator": {"name": creator.name, "email": creator.email, "role": creator.role} if creator else None,
            "assignee": {"name": assigned.name, "email": assigned.email, "role": assigned.role} if assigned else None,
        },
        "agent": {
            "id": agent.id,
            "name": agent.name,
            "purpose": agent.purpose,
            "risk_category": getattr(agent, "risk_category", agent.risk_tier),
            "status": agent.status,
            "cost_per_call": getattr(agent, "cost_per_call", 0.01),
            "permitted_actions": getattr(agent, "permitted_actions", []),
            "data_access": getattr(agent, "data_access", []),
            "breach_count": getattr(agent, "breach_count", 0),
        }
        if agent
        else None,
        "owner": {
            "id": owner.id,
            "name": owner.name,
            "email": owner.email,
            "role": owner.role,
        }
        if owner
        else None,
        "action": {
            "id": ar.id,
            "tool": ar.tool,
            "params": ar.params,
            "params_hash": ar.params_hash,
            "data_used": getattr(ar, "data_used", []),
            "sensitivity": ar.sensitivity,
            "status": ar.status,
            "decision": ar.decision,
            "reason": ar.reason,
            "is_breach": getattr(ar, "is_breach", False),
            "breach_reason": getattr(ar, "breach_reason", None),
            "created_at": ar.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if ar.created_at else None,
            "result": ar.result,
        }
        if ar
        else None,
        "policy_rule": {
            "rule_id": ar.matched_rule_id if ar else None,
            "version": ar.policy_version if ar else None,
            "details": rule_info,
        }
        if (ar and ar.matched_rule_id)
        else None,
        "approver": {
            "id": approver.id,
            "name": approver.name,
            "email": approver.email,
            "decided_at": ar.decided_at.strftime("%Y-%m-%d %H:%M:%S UTC") if ar and ar.decided_at else None,
            "reason": ar.decision_reason if ar else None,
        }
        if approver
        else None,
        "ledger_trail": [
            {
                "seq": entry.seq,
                "event_type": entry.event_type,
                "actor_type": entry.actor_type,
                "actor_id": entry.actor_id,
                "hash": entry.hash,
                "prev_hash": entry.prev_hash,
                "ts": entry.ts.strftime("%Y-%m-%d %H:%M:%S UTC") if entry.ts else None,
                "payload": entry.payload,
            }
            for entry in ledger_entries
        ],
    }


def get_incident_metrics(db: Session) -> dict[str, Any]:
    """Calculate aggregated governance incident statistics."""
    incidents = list(db.execute(select(Incident)).scalars().all())
    total = len(incidents)
    open_count = sum(1 for inc in incidents if inc.status == "open")
    investigating_count = sum(1 for inc in incidents if inc.status == "investigating")
    resolved_count = sum(1 for inc in incidents if inc.status == "resolved")

    by_severity = {
        "critical": sum(1 for inc in incidents if inc.severity == "critical"),
        "high": sum(1 for inc in incidents if inc.severity == "high"),
        "medium": sum(1 for inc in incidents if inc.severity == "medium"),
        "low": sum(1 for inc in incidents if inc.severity == "low"),
    }

    return {
        "total": total,
        "open": open_count,
        "investigating": investigating_count,
        "resolved": resolved_count,
        "by_severity": by_severity,
    }

