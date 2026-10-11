"""SLA watcher – escalates pending requests past their deadline."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime

from sqlalchemy import select

from app import ledger
from app.db import SessionLocal
from app.models import ActionRequest

logger = logging.getLogger("agentwarden.escalation")

_task: asyncio.Task | None = None
_stop = asyncio.Event()


def escalate_overdue(db) -> int:
    """Mark overdue pending requests as escalated. Returns count escalated."""
    now = datetime.now(UTC)
    q = (
        select(ActionRequest)
        .where(ActionRequest.status == "pending")
        .where(ActionRequest.sla_deadline.isnot(None))
        .where(ActionRequest.sla_deadline < now)
    )
    rows = list(db.execute(q).scalars().all())
    count = 0
    for ar in rows:
        ar.status = "escalated"
        ar.escalated_at = now
        ledger.append(
            db,
            event_type="escalated",
            actor_type="system",
            actor_id="sla_watcher",
            subject_type="action_request",
            subject_id=str(ar.id),
            payload={"sla_deadline": ar.sla_deadline.isoformat() if ar.sla_deadline else None},
            policy_version=ar.policy_version,
            ts=now,
        )
        count += 1
    if count:
        db.commit()
    return count


async def _loop(interval: float = 3.0) -> None:
    while not _stop.is_set():
        try:
            db = SessionLocal()
            try:
                n = escalate_overdue(db)
                if n:
                    logger.info("escalated %d requests", n)
            finally:
                db.close()
        except Exception:
            logger.exception("escalation tick failed")
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(_stop.wait(), timeout=interval)


def start_escalation_task(interval: float = 3.0) -> None:
    global _task
    _stop.clear()
    if _task is None or _task.done():
        _task = asyncio.create_task(_loop(interval))


def stop_escalation_task() -> None:
    _stop.set()
