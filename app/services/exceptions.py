"""Exception case lifecycle management for agent failures and breaches."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger
from app.models import ExceptionCase, User


class ExceptionError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def open_exception(
    db: Session,
    title: str,
    agent_id: int | None = None,
    action_request_id: int | None = None,
    severity: str = "high",
    assigned_user_id: int | None = None,
    initial_note: str | None = None,
) -> ExceptionCase:
    now = datetime.now(UTC)
    exc = ExceptionCase(
        title=title,
        agent_id=agent_id,
        action_request_id=action_request_id,
        status="open",
        severity=severity,
        assigned_user_id=assigned_user_id,
        resolution_note=initial_note,
        created_at=now,
    )
    db.add(exc)
    db.flush()

    ledger.append(
        db,
        event_type="exception_opened",
        actor_type="system",
        actor_id="exception_service",
        subject_type="exception_case",
        subject_id=str(exc.id),
        payload={
            "title": title,
            "agent_id": agent_id,
            "action_id": action_request_id,
            "severity": severity,
            "assigned_user_id": assigned_user_id,
        },
        ts=now,
    )
    db.flush()
    return exc


def start_investigation(db: Session, exception_id: int, user: User) -> ExceptionCase:
    exc = db.execute(select(ExceptionCase).where(ExceptionCase.id == exception_id)).scalar_one_or_none()
    if exc is None:
        raise ExceptionError("not_found", "Exception case not found")
    if exc.status == "resolved":
        raise ExceptionError("already_resolved", "Exception case is already resolved")

    exc.status = "investigating"
    exc.assigned_user_id = user.id
    db.flush()
    return exc


def resolve_exception(
    db: Session,
    exception_id: int,
    user: User,
    resolution_note: str,
) -> ExceptionCase:
    if len(resolution_note.strip()) < 10:
        raise ExceptionError("invalid_note", "Resolution note must be at least 10 characters")

    exc = db.execute(select(ExceptionCase).where(ExceptionCase.id == exception_id)).scalar_one_or_none()
    if exc is None:
        raise ExceptionError("not_found", "Exception case not found")
    if exc.status == "resolved":
        raise ExceptionError("already_resolved", "Exception case is already resolved")

    now = datetime.now(UTC)
    exc.status = "resolved"
    exc.resolution_note = resolution_note.strip()
    exc.resolved_at = now
    exc.assigned_user_id = user.id

    ledger.append(
        db,
        event_type="exception_resolved",
        actor_type="user",
        actor_id=str(user.id),
        subject_type="exception_case",
        subject_id=str(exc.id),
        payload={
            "resolution_note": resolution_note.strip(),
            "resolved_by": user.name,
        },
        ts=now,
    )
    db.flush()
    return exc
