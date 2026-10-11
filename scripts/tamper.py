"""Tamper with one ledger row for the verification demo.

Usage: PYTHONPATH=. python scripts/tamper.py [--repair]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select

from app.db import SessionLocal, init_db
from app.models import LedgerEntry

BACKUP_PATH = Path(__file__).resolve().parents[1] / ".tamper_backup.json"


def tamper() -> None:
    init_db()
    db = SessionLocal()
    try:
        entries = list(
            db.execute(select(LedgerEntry).order_by(LedgerEntry.seq.desc()).limit(20))
            .scalars()
            .all()
        )
        target = None
        for e in entries:
            if e.event_type == "decision_made":
                target = e
                break
        if target is None and entries:
            target = entries[0]
        if target is None:
            print("No ledger entries to tamper with")
            return
        BACKUP_PATH.write_text(
            json.dumps(
                {
                    "seq": target.seq,
                    "payload": target.payload,
                    "hash": target.hash,
                }
            )
        )
        old = dict(target.payload or {})
        old["_tampered"] = True
        target.payload = old
        db.commit()
        print(f"Tampered ledger seq={target.seq} (backup at {BACKUP_PATH})")
    finally:
        db.close()


def repair() -> None:
    if not BACKUP_PATH.exists():
        print("No backup found")
        return
    data = json.loads(BACKUP_PATH.read_text())
    init_db()
    db = SessionLocal()
    try:
        e = db.execute(
            select(LedgerEntry).where(LedgerEntry.seq == data["seq"])
        ).scalar_one_or_none()
        if e is None:
            print("Entry not found")
            return
        e.payload = data["payload"]
        e.hash = data["hash"]
        db.commit()
        print(f"Restored seq={data['seq']}")
        BACKUP_PATH.unlink(missing_ok=True)
    finally:
        db.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--repair", action="store_true")
    args = p.parse_args()
    if args.repair:
        repair()
    else:
        tamper()
