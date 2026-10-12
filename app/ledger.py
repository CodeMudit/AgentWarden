"""Append-only hash-chained ledger."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import LedgerEntry, LedgerHead

GENESIS_PREV = "0" * 64

EVENT_TYPES = frozenset(
    {
        "agent_registered",
        "agent_suspended",
        "agent_resumed",
        "agent_restricted",
        "agent_paused",
        "policy_breach_detected",
        "work_item_created",
        "work_item_routed",
        "work_item_completed",
        "exception_opened",
        "exception_resolved",
        "incident_opened",
        "incident_resolved",
        "system_frozen",
        "system_unfrozen",
        "action_requested",
        "decision_made",
        "approval_requested",
        "approved",
        "rejected",
        "escalated",
        "action_completed",
        "param_mismatch_blocked",
        "policy_created",
        "policy_activated",
        "user_login",
        "ledger_verified",
        "checkpoint_created",
        "token_issued",
        "token_consumed",
        "token_replay_blocked",
        "token_invalid",
        "checkpoint_anchored",
    }
)


def canonical_json(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    material = prev_hash + canonical_json(payload)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _ensure_head(db: Session) -> LedgerHead:
    head = db.execute(select(LedgerHead).limit(1)).scalar_one_or_none()
    if head is None:
        head = LedgerHead(last_seq=0, last_hash=GENESIS_PREV)
        db.add(head)
        db.flush()
    return head


def _lock_head(db: Session) -> LedgerHead:
    """Lock LedgerHead for concurrent-safe append.

    Postgres: SELECT ... FOR UPDATE.
    SQLite: rely on write lock from the UPDATE of LedgerHead in the same
    transaction; optionally escalate with BEGIN IMMEDIATE when not already
    inside a transaction.
    """
    settings = get_settings()
    if settings.is_sqlite:
        try:
            # Escalate to IMMEDIATE only when the connection has no active txn yet
            conn = db.connection()
            sync_conn = conn.connection  # DBAPI connection
            if not getattr(sync_conn, "in_transaction", lambda: True)():
                db.execute(text("BEGIN IMMEDIATE"))
        except Exception:
            pass  # already in a transaction – fine for single-writer SQLite tests
        head = _ensure_head(db)
        # Force a write lock by touching the row
        head.last_seq = head.last_seq
        db.flush()
        return head
    head = _ensure_head(db)
    head = db.execute(select(LedgerHead).with_for_update().limit(1)).scalar_one()
    return head


def append(
    db: Session,
    *,
    event_type: str,
    actor_type: str,
    actor_id: str | None = None,
    subject_type: str | None = None,
    subject_id: str | None = None,
    payload: dict[str, Any] | None = None,
    policy_version: int | None = None,
    ts: datetime | None = None,
) -> LedgerEntry:
    """Append a ledger entry inside the caller's transaction (locks head)."""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown event_type: {event_type}")

    head = _lock_head(db)
    next_seq = head.last_seq + 1
    prev_hash = head.last_hash
    ts = ts or datetime.now(UTC)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)

    body = {
        "seq": next_seq,
        "ts": ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "event_type": event_type,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "payload": payload or {},
        "policy_version": policy_version,
    }
    entry_hash = compute_hash(prev_hash, body)

    entry = LedgerEntry(
        seq=next_seq,
        ts=ts,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        subject_type=subject_type,
        subject_id=subject_id,
        payload=payload or {},
        policy_version=policy_version,
        prev_hash=prev_hash,
        hash=entry_hash,
    )
    db.add(entry)
    head.last_seq = next_seq
    head.last_hash = entry_hash
    db.flush()
    return entry


def ensure_genesis(db: Session) -> LedgerEntry | None:
    """Create genesis entry (seq 1) if ledger is empty. Returns the genesis entry or None."""
    head = _ensure_head(db)
    if head.last_seq > 0:
        return None
    return append(
        db,
        event_type="checkpoint_created",
        actor_type="system",
        actor_id="system",
        subject_type="ledger",
        subject_id="genesis",
        payload={"note": "genesis"},
    )


def verify(db: Session) -> dict[str, Any]:
    """Recompute every hash from seq 1. Detects edits, gaps, reorder, bad prev_hash."""
    entries = list(db.execute(select(LedgerEntry).order_by(LedgerEntry.seq.asc())).scalars().all())
    if not entries:
        return {
            "ok": True,
            "checked": 0,
            "first_broken_seq": None,
            "expected_hash": None,
            "found_hash": None,
            "reason": "empty ledger",
        }

    expected_prev = GENESIS_PREV
    expected_seq = 1
    for entry in entries:
        if entry.seq != expected_seq:
            return {
                "ok": False,
                "checked": expected_seq - 1,
                "first_broken_seq": entry.seq,
                "expected_hash": None,
                "found_hash": entry.hash,
                "reason": f"seq gap: expected {expected_seq}, found {entry.seq}",
            }
        if entry.prev_hash != expected_prev:
            return {
                "ok": False,
                "checked": expected_seq - 1,
                "first_broken_seq": entry.seq,
                "expected_hash": None,
                "found_hash": entry.hash,
                "reason": f"prev_hash mismatch at seq {entry.seq}",
            }
        body = {
            "seq": entry.seq,
            "ts": entry.ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            if entry.ts.tzinfo
            else entry.ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "event_type": entry.event_type,
            "actor_type": entry.actor_type,
            "actor_id": entry.actor_id,
            "subject_type": entry.subject_type,
            "subject_id": entry.subject_id,
            "payload": entry.payload or {},
            "policy_version": entry.policy_version,
        }
        # Re-canonicalize ts from stored value — use ISO format matching append
        ts = entry.ts
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        body["ts"] = ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        expected_hash = compute_hash(entry.prev_hash, body)
        if expected_hash != entry.hash:
            return {
                "ok": False,
                "checked": expected_seq - 1,
                "first_broken_seq": entry.seq,
                "expected_hash": expected_hash,
                "found_hash": entry.hash,
                "reason": f"hash mismatch at seq {entry.seq} (payload or hash edited)",
            }
        expected_prev = entry.hash
        expected_seq += 1

    return {
        "ok": True,
        "checked": len(entries),
        "first_broken_seq": None,
        "expected_hash": None,
        "found_hash": entries[-1].hash if entries else None,
        "reason": "chain intact",
    }


def create_checkpoint(db: Session) -> dict[str, Any]:
    settings = get_settings()
    head = _ensure_head(db)
    ts = datetime.now(UTC)
    msg = f"{head.last_seq}:{head.last_hash}:{ts.isoformat()}"
    sig = hmac.new(
        settings.ledger_checkpoint_key.encode("utf-8"),
        msg.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "seq": head.last_seq,
        "hash": head.last_hash,
        "ts": ts.isoformat(),
        "hmac": sig,
    }


def verify_checkpoint(db: Session, checkpoint: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    seq = checkpoint.get("seq")
    h = checkpoint.get("hash")
    ts = checkpoint.get("ts")
    provided_hmac = checkpoint.get("hmac")
    msg = f"{seq}:{h}:{ts}"
    expected = hmac.new(
        settings.ledger_checkpoint_key.encode("utf-8"),
        msg.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    hmac_ok = hmac.compare_digest(expected, provided_hmac or "")
    head = _ensure_head(db)
    chain_ok = head.last_seq >= (seq or 0)
    # Check that the entry at that seq still has that hash
    entry = None
    if seq:
        entry = db.execute(select(LedgerEntry).where(LedgerEntry.seq == seq)).scalar_one_or_none()
    entry_ok = entry is not None and entry.hash == h
    ok = hmac_ok and entry_ok
    reason = "valid"
    if not hmac_ok:
        reason = "HMAC mismatch"
    elif not entry_ok:
        reason = "entry hash no longer matches checkpoint (possible rewrite)"
    return {
        "ok": ok,
        "hmac_ok": hmac_ok,
        "entry_ok": entry_ok,
        "chain_ok": chain_ok,
        "reason": reason,
        "current_head_seq": head.last_seq,
        "current_head_hash": head.last_hash,
    }


def get_head(db: Session) -> dict[str, Any]:
    head = _ensure_head(db)
    return {"last_seq": head.last_seq, "last_hash": head.last_hash}
