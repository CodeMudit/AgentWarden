"""Ledger list / verify / checkpoint / export."""

from __future__ import annotations

import csv
import io
import json

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger
from app.db import get_db
from app.models import LedgerEntry, User
from app.schemas import CheckpointIn, LedgerEntryOut
from app.security import require_reviewer_or_admin

router = APIRouter(prefix="/ledger", tags=["ledger"])


@router.get("", response_model=list[LedgerEntryOut])
def list_entries(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    event_type: str | None = None,
    user: User = Depends(require_reviewer_or_admin),
    db: Session = Depends(get_db),
):
    q = select(LedgerEntry).order_by(LedgerEntry.seq.desc())
    if event_type:
        q = q.where(LedgerEntry.event_type == event_type)
    q = q.offset(offset).limit(limit)
    rows = list(db.execute(q).scalars().all())
    return [LedgerEntryOut.model_validate(e) for e in rows]


@router.get("/head")
def ledger_head(
    user: User = Depends(require_reviewer_or_admin),
    db: Session = Depends(get_db),
):
    return ledger.get_head(db)


@router.post("/verify")
def verify_ledger(
    user: User = Depends(require_reviewer_or_admin),
    db: Session = Depends(get_db),
):
    result = ledger.verify(db)
    ledger.append(
        db,
        event_type="ledger_verified",
        actor_type="user",
        actor_id=str(user.id),
        subject_type="ledger",
        subject_id="chain",
        payload={"ok": result["ok"], "checked": result["checked"]},
    )
    db.commit()
    return result


@router.post("/checkpoint")
def checkpoint(
    user: User = Depends(require_reviewer_or_admin),
    db: Session = Depends(get_db),
):
    cp = ledger.create_checkpoint(db)
    ledger.append(
        db,
        event_type="checkpoint_created",
        actor_type="user",
        actor_id=str(user.id),
        subject_type="ledger",
        subject_id="checkpoint",
        payload={"seq": cp["seq"], "hash": cp["hash"]},
    )
    db.commit()
    return cp


@router.post("/verify-checkpoint")
def verify_cp(
    body: CheckpointIn,
    user: User = Depends(require_reviewer_or_admin),
    db: Session = Depends(get_db),
):
    return ledger.verify_checkpoint(db, body.model_dump())


@router.get("/export")
def export_ledger(
    fmt: str = Query("json", pattern="^(json|csv)$"),
    user: User = Depends(require_reviewer_or_admin),
    db: Session = Depends(get_db),
):
    entries = list(db.execute(select(LedgerEntry).order_by(LedgerEntry.seq.asc())).scalars().all())
    verification = ledger.verify(db)
    head = ledger.get_head(db)

    if fmt == "csv":
        buf = io.StringIO()
        buf.write(f"# verification_ok={verification['ok']} checked={verification['checked']}\n")
        buf.write(f"# head_seq={head['last_seq']} head_hash={head['last_hash']}\n")
        writer = csv.writer(buf)
        writer.writerow(
            [
                "seq",
                "ts",
                "event_type",
                "actor_type",
                "actor_id",
                "subject_type",
                "subject_id",
                "policy_version",
                "prev_hash",
                "hash",
                "payload",
            ]
        )
        for e in entries:
            writer.writerow(
                [
                    e.seq,
                    e.ts.isoformat(),
                    e.event_type,
                    e.actor_type,
                    e.actor_id,
                    e.subject_type,
                    e.subject_id,
                    e.policy_version,
                    e.prev_hash,
                    e.hash,
                    json.dumps(e.payload),
                ]
            )
        return PlainTextResponse(buf.getvalue(), media_type="text/csv")

    payload = {
        "verification": verification,
        "head": head,
        "entries": [LedgerEntryOut.model_validate(e).model_dump(mode="json") for e in entries],
    }
    return Response(
        content=json.dumps(payload, default=str, indent=2),
        media_type="application/json",
    )
