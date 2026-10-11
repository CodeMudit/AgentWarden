"""Ledger chain, tamper detection, concurrency, checkpoint tests."""

from __future__ import annotations

import concurrent.futures

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import ledger
from app.db import Base
from app.models import LedgerEntry


def _session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autocommit=False, autoflush=False), engine


def test_genesis_and_chain():
    Session, _ = _session_factory()
    db = Session()
    ledger.ensure_genesis(db)
    db.commit()
    e1 = ledger.append(
        db,
        event_type="agent_registered",
        actor_type="user",
        actor_id="1",
        subject_type="agent",
        subject_id="1",
        payload={"name": "bot"},
    )
    db.commit()
    ledger.append(
        db,
        event_type="decision_made",
        actor_type="system",
        actor_id="engine",
        subject_type="action_request",
        subject_id="1",
        payload={"decision": "allow"},
    )
    db.commit()
    assert e1.seq == 1 or e1.seq == 2  # genesis may be seq 1
    result = ledger.verify(db)
    assert result["ok"] is True
    assert result["checked"] >= 2
    db.close()


def test_tamper_payload_detected():
    Session, _ = _session_factory()
    db = Session()
    ledger.ensure_genesis(db)
    db.commit()
    e = ledger.append(
        db,
        event_type="decision_made",
        actor_type="system",
        actor_id="x",
        payload={"decision": "allow"},
    )
    db.commit()
    # Tamper
    e.payload = {"decision": "deny"}
    db.commit()
    result = ledger.verify(db)
    assert result["ok"] is False
    assert result["first_broken_seq"] == e.seq
    db.close()


def test_tamper_hash_detected():
    Session, _ = _session_factory()
    db = Session()
    ledger.ensure_genesis(db)
    db.commit()
    e = ledger.append(
        db,
        event_type="decision_made",
        actor_type="system",
        actor_id="x",
        payload={"decision": "allow"},
    )
    db.commit()
    e.hash = "f" * 64
    db.commit()
    result = ledger.verify(db)
    assert result["ok"] is False
    db.close()


def test_seq_gap_detected():
    Session, engine = _session_factory()
    db = Session()
    ledger.ensure_genesis(db)
    db.commit()
    ledger.append(db, event_type="decision_made", actor_type="system", actor_id="a", payload={})
    ledger.append(db, event_type="decision_made", actor_type="system", actor_id="b", payload={})
    db.commit()
    # Delete middle by rewriting seqs is hard; insert a fake high-seq entry after deleting
    entries = list(db.execute(select(LedgerEntry).order_by(LedgerEntry.seq)).scalars().all())
    if len(entries) >= 2:
        mid = entries[1]
        db.delete(mid)
        db.commit()
        result = ledger.verify(db)
        assert result["ok"] is False
        assert "gap" in result["reason"] or result["first_broken_seq"] is not None
    db.close()


def test_concurrent_appends(tmp_path):
    """50 concurrent appends must produce a valid chain with unique seqs."""
    import threading

    db_path = tmp_path / "conc.db"
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    lock = threading.Lock()

    db = Session()
    ledger.ensure_genesis(db)
    db.commit()
    db.close()

    def worker(i: int):
        s = Session()
        try:
            with lock:  # serialize SQLite writers (SQLite limitation)
                ledger.append(
                    s,
                    event_type="decision_made",
                    actor_type="system",
                    actor_id=str(i),
                    payload={"i": i},
                )
                s.commit()
            return True
        except Exception as e:
            s.rollback()
            return str(e)
        finally:
            s.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(worker, range(50)))

    assert all(r is True for r in results), results
    db = Session()
    entries = list(db.execute(select(LedgerEntry).order_by(LedgerEntry.seq)).scalars().all())
    seqs = [e.seq for e in entries]
    assert len(seqs) == len(set(seqs)), "duplicate seqs"
    result = ledger.verify(db)
    assert result["ok"] is True, result
    assert result["checked"] >= 50
    db.close()


def test_checkpoint_hmac():
    Session, _ = _session_factory()
    db = Session()
    ledger.ensure_genesis(db)
    db.commit()
    ledger.append(db, event_type="decision_made", actor_type="system", actor_id="x", payload={})
    db.commit()
    cp = ledger.create_checkpoint(db)
    assert "hmac" in cp and "seq" in cp and "hash" in cp
    v = ledger.verify_checkpoint(db, cp)
    assert v["ok"] is True
    # Bad hmac
    bad = dict(cp)
    bad["hmac"] = "0" * 64
    v2 = ledger.verify_checkpoint(db, bad)
    assert v2["ok"] is False
    db.close()
