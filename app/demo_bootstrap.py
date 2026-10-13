"""Auto-seed demo data on an empty database (DEMO_MODE only).

Why: on a fresh hosted deployment nobody has run ``scripts/seed.py``, so there are no users
and nobody can log in. ``ensure_demo_data`` creates the demo accounts, agents, policy and
history the first time the app sees an empty users table.

Tables must already exist (the app lifespan runs ``init_db`` first). If they don't, the
user count query fails, the error is logged, and nothing is seeded.

Safety rules:
- Does nothing unless ``DEMO_MODE=true``.
- Does nothing if any user already exists. It NEVER resets or overwrites existing data.
- On PostgreSQL a session-level advisory lock stops two instances seeding at once.
- Never raises: a failed seed is logged and the app keeps running.
"""

from __future__ import annotations

import logging

from sqlalchemy import func, select, text

from app.config import get_settings
from app.db import SessionLocal, engine
from app.models import User

logger = logging.getLogger("agentwarden.bootstrap")

_LOCK_KEY = 726_351_001  # arbitrary constant, unique to this app


def _users_exist() -> bool:
    db = SessionLocal()
    try:
        return (db.execute(select(func.count(User.id))).scalar() or 0) > 0
    finally:
        db.close()


def ensure_demo_data() -> bool:
    """Seed demo data if DEMO_MODE is on and the DB has no users. Returns True if it seeded."""
    if not get_settings().demo_mode:
        return False
    try:
        if _users_exist():
            return False

        lock_conn = None
        if engine.dialect.name == "postgresql":
            lock_conn = engine.connect()
            got = lock_conn.execute(
                text("SELECT pg_try_advisory_lock(:k)"), {"k": _LOCK_KEY}
            ).scalar()
            if not got:
                logger.info("another instance is seeding demo data; skipping")
                lock_conn.close()
                return False
        try:
            if _users_exist():  # re-check now that we hold the lock
                return False
            from scripts.seed import run_seed

            logger.warning("empty database in DEMO_MODE: seeding demo data")
            db = SessionLocal()
            try:
                run_seed(db, reset=False, verbose=False)
            finally:
                db.close()
            return True
        finally:
            if lock_conn is not None:
                lock_conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": _LOCK_KEY})
                lock_conn.close()
    except Exception:
        logger.exception("demo bootstrap failed; continuing without seed data")
        return False
