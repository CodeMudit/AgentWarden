"""Idempotent DEMO_MODE policy upgrade for the /judge flow.

The hosted database was seeded before these rules existed, and ``ensure_demo_data`` never
touches a non-empty DB. This adds the rules as a NEW policy version (the old one stays in
history) the first time it runs, and does nothing afterwards.
"""

from __future__ import annotations

import copy
import logging

from sqlalchemy import select

from app import ledger
from app.config import get_settings
from app.db import SessionLocal
from app.models import Policy, User

logger = logging.getLogger("agentwarden.judge_policy")

JUDGE_AGENT_PREFIX = "judge-"

# Deny-list is demo-grade (see docs/DEMO_SCRIPT.md). The point is a named, visible rule.
DESTRUCTIVE_SQL = (
    r"(?is)(\b(drop|delete|truncate|update|alter|insert|grant|revoke|create|copy)\b|;\s*\S)"
)

JUDGE_RULES = [
    {
        "id": "sql-block-destructive",
        "priority": 1,
        "description": (
            "Destructive or multi-statement SQL is never allowed. "
            "A second attempt by the same agent counts as a breach and pauses it"
        ),
        "match": {"tools": ["run_readonly_query", "run_sql", "export_csv"]},
        "conditions": [{"type": "param_matches", "field": "query", "value": DESTRUCTIVE_SQL}],
        "effect": "deny",
        "repeat_breach_pause": True,
    },
    {
        "id": "judge-refund-small-auto",
        "priority": 10,
        "description": "Sandbox agents: refunds up to 100 are auto-approved",
        "match": {"agent_prefix": JUDGE_AGENT_PREFIX, "tools": ["issue_refund"]},
        "conditions": [{"type": "amount_lte", "field": "amount", "value": 100}],
        "effect": "allow",
    },
    {
        "id": "judge-refund-large-review",
        "priority": 20,
        "description": "Sandbox agents: refunds over 100 need a human reviewer",
        "match": {"agent_prefix": JUDGE_AGENT_PREFIX, "tools": ["issue_refund"]},
        "conditions": [{"type": "amount_gt", "field": "amount", "value": 100}],
        "effect": "require_approval",
    },
]


def merged_policy(current: dict) -> dict | None:
    """Return current policy + missing judge rules, or None if nothing to add."""
    doc = copy.deepcopy(current or {"default_effect": "deny", "rules": []})
    have = {r.get("id") for r in doc.get("rules") or []}
    missing = [r for r in JUDGE_RULES if r["id"] not in have]
    if not missing:
        return None
    doc.setdefault("rules", []).extend(copy.deepcopy(missing))
    return doc


def ensure_judge_policy() -> bool:
    """DEMO_MODE only. Never raises. Returns True if a new policy version was activated."""
    if not get_settings().demo_mode:
        return False
    db = SessionLocal()
    try:
        active = db.execute(select(Policy).where(Policy.is_active.is_(True))).scalar_one_or_none()
        if active is None:
            return False  # nothing seeded yet; scripts.seed will include nothing of ours
        doc = merged_policy(active.rules)
        if doc is None:
            return False
        admin = db.execute(select(User).where(User.role == "admin").order_by(User.id)).scalars().first()
        max_v = db.execute(select(Policy.version).order_by(Policy.version.desc()).limit(1)).scalar()
        version = (max_v or 0) + 1
        active.is_active = False
        new = Policy(
            version=version,
            rules=doc,
            is_active=True,
            created_by=admin.id if admin else None,
            note="Added judge-demo rules (SQL deny, sandbox refund review)",
        )
        db.add(new)
        db.flush()
        actor = str(admin.id) if admin else "system"
        for ev in ("policy_created", "policy_activated"):
            ledger.append(
                db,
                event_type=ev,
                actor_type="user" if admin else "system",
                actor_id=actor,
                subject_type="policy",
                subject_id=str(new.id),
                payload={"version": version},
                policy_version=version,
            )
        db.commit()
        logger.warning("activated policy v%s with judge rules", version)
        return True
    except Exception:
        db.rollback()
        logger.exception("ensure_judge_policy failed; continuing")
        return False
    finally:
        db.close()
