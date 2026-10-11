"""Seed demo data: users, agents, policy, historical requests via real services.

Usage:
  PYTHONPATH=. python scripts/seed.py
  PYTHONPATH=. python scripts/seed.py --reset
"""

from __future__ import annotations

import argparse
import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Ensure repo root on path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rich.console import Console
from sqlalchemy import delete, select

from app import ledger
from app.db import SessionLocal, init_db
from app.models import ActionRequest, Agent, LedgerEntry, LedgerHead, Policy, SystemState, User
from app.security import generate_api_key, hash_password
from app.services import actions as actions_svc

console = Console()

DEMO_POLICY = {
    "default_effect": "deny",
    "rules": [
        {
            "id": "rate-limit-refund",
            "priority": 3,
            "description": "Deny refund bursts over 5/min",
            "match": {"agents": ["refund-bot"], "tools": ["issue_refund"]},
            "conditions": [{"type": "rate_limit", "value": {"max": 5, "window_seconds": 60}}],
            "effect": "deny",
        },
        {
            "id": "block-external-pii",
            "priority": 5,
            "description": "Block PII email to external domains",
            "match": {"tools": ["send_email"]},
            "conditions": [
                {"type": "domain_not_in", "field": "to", "value": ["company.com"]},
                {"type": "sensitivity_in", "value": ["confidential", "pii"]},
            ],
            "effect": "deny",
        },
        {
            "id": "refund-small-auto",
            "priority": 10,
            "description": "Refunds up to 100 are auto-approved",
            "match": {"agents": ["refund-bot"], "tools": ["issue_refund"]},
            "conditions": [{"type": "amount_lte", "field": "amount", "value": 100}],
            "effect": "allow",
        },
        {
            "id": "refund-large-review",
            "priority": 20,
            "description": "Large refunds need human approval",
            "match": {"agents": ["refund-bot"], "tools": ["issue_refund"]},
            "conditions": [{"type": "amount_gt", "field": "amount", "value": 100}],
            "effect": "require_approval",
        },
        {
            "id": "internal-email-allow",
            "priority": 15,
            "match": {"agents": ["email-assistant"], "tools": ["send_email"]},
            "conditions": [
                {"type": "domain_in", "field": "to", "value": ["company.com"]},
            ],
            "effect": "allow",
        },
    ],
}


def reset_db(db) -> None:
    console.print("[yellow]Resetting all data…[/yellow]")
    for table in (ActionRequest, LedgerEntry, Agent, Policy, User, SystemState, LedgerHead):
        db.execute(delete(table))
    db.commit()
    ledger.ensure_genesis(db)
    db.commit()


def seed_users(db) -> dict[str, User]:
    specs = [
        ("admin@demo.local", "Demo Admin", "demo-admin-pass", "admin"),
        ("admin2@demo.local", "Demo Admin 2", "demo-admin-pass", "admin"),
        ("reviewer_a@demo.local", "Reviewer A", "demo-reviewer-pass", "reviewer"),
        ("reviewer_b@demo.local", "Reviewer B", "demo-reviewer-pass", "reviewer"),
        ("auditor@demo.local", "Auditor", "demo-auditor-pass", "auditor"),
    ]
    users = {}
    for email, name, password, role in specs:
        existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if existing:
            users[email] = existing
            continue
        u = User(
            email=email,
            name=name,
            password_hash=hash_password(password),
            role=role,
            is_active=True,
        )
        db.add(u)
        db.flush()
        users[email] = u
    db.commit()
    return users


def seed_agents(db, users: dict[str, User]) -> dict[str, tuple[Agent, str]]:
    """Return name -> (agent, api_key)."""
    result = {}
    specs = [
        ("refund-bot", "Issues customer refunds", users["reviewer_a@demo.local"].id, "medium"),
        ("email-assistant", "Sends customer emails", users["reviewer_b@demo.local"].id, "high"),
    ]
    for name, purpose, owner_id, tier in specs:
        existing = db.execute(select(Agent).where(Agent.name == name)).scalar_one_or_none()
        if existing:
            # Can't recover full key – generate new for seed re-run of history only if missing
            result[name] = (existing, None)
            continue
        full, prefix, key_hash = generate_api_key()
        agent = Agent(
            name=name,
            purpose=purpose,
            owner_user_id=owner_id,
            risk_tier=tier,
            status="active",
            api_key_prefix=prefix,
            api_key_hash=key_hash,
        )
        db.add(agent)
        db.flush()
        ledger.append(
            db,
            event_type="agent_registered",
            actor_type="user",
            actor_id=str(owner_id),
            subject_type="agent",
            subject_id=str(agent.id),
            payload={"name": name},
        )
        result[name] = (agent, full)
    db.commit()
    return result


def seed_policy(db, admin: User) -> Policy:
    existing = db.execute(select(Policy).where(Policy.is_active.is_(True))).scalar_one_or_none()
    if existing:
        return existing
    max_v = db.execute(select(Policy.version).order_by(Policy.version.desc()).limit(1)).scalar()
    version = (max_v or 0) + 1
    p = Policy(
        version=version,
        rules=DEMO_POLICY,
        is_active=True,
        created_by=admin.id,
        note="Demo seed policy",
    )
    db.add(p)
    db.flush()
    ledger.append(
        db,
        event_type="policy_created",
        actor_type="user",
        actor_id=str(admin.id),
        subject_type="policy",
        subject_id=str(p.id),
        payload={"version": version},
        policy_version=version,
    )
    ledger.append(
        db,
        event_type="policy_activated",
        actor_type="user",
        actor_id=str(admin.id),
        subject_type="policy",
        subject_id=str(p.id),
        payload={"version": version},
        policy_version=version,
    )
    db.commit()
    return p


def seed_history(db, agents: dict[str, tuple[Agent, str | None]], n: int = 50) -> None:
    """Generate realistic historical requests through the real service layer."""
    from sqlalchemy import func as sqla_func

    existing = db.execute(sqla_func.count(ActionRequest.id)).scalar() or 0
    if existing > 10:
        console.print(f"[dim]History already present ({existing} actions), skipping[/dim]")
        return

    refund_bot = agents["refund-bot"][0]
    email_bot = agents["email-assistant"][0]
    now = datetime.now(UTC)
    rng = random.Random(42)

    scenarios = []
    for i in range(n):
        roll = rng.random()
        ts = now - timedelta(hours=rng.randint(1, 168), minutes=rng.randint(0, 59))
        if roll < 0.45:
            amount = rng.choice([10, 25, 40, 50, 75, 90, 100])
            scenarios.append(
                (
                    refund_bot,
                    "issue_refund",
                    {"amount": amount, "order_id": f"ORD-{1000 + i}"},
                    "internal",
                    ts,
                )
            )
        elif roll < 0.65:
            amount = rng.choice([150, 200, 350, 500, 900, 1200])
            scenarios.append(
                (
                    refund_bot,
                    "issue_refund",
                    {"amount": amount, "order_id": f"ORD-{2000 + i}"},
                    "internal",
                    ts,
                )
            )
        elif roll < 0.80:
            scenarios.append(
                (
                    email_bot,
                    "send_email",
                    {"to": "customer@gmail.com", "subject": "Customer Export"},
                    "pii",
                    ts,
                )
            )
        else:
            scenarios.append(
                (
                    email_bot,
                    "send_email",
                    {"to": "alice@company.com", "subject": f"Update {i}"},
                    "internal",
                    ts,
                )
            )

    # Sort by time so rate limits and chronology make sense
    scenarios.sort(key=lambda x: x[4])

    from app.models import User as UserModel
    from app.services.approvals import approve, reject

    reviewer_b = db.execute(
        select(UserModel).where(UserModel.email == "reviewer_b@demo.local")
    ).scalar_one()
    reviewer_a = db.execute(
        select(UserModel).where(UserModel.email == "reviewer_a@demo.local")
    ).scalar_one()

    created = 0
    for agent, tool, params, sensitivity, ts in scenarios:
        ar = actions_svc.request_action(
            db, agent=agent, tool=tool, params=params, sensitivity=sensitivity
        )
        # Backdate created_at for charts
        ar.created_at = ts
        if ar.status == "pending":
            # Auto-resolve some historical pendings so queue isn't full of ancient items
            if rng.random() < 0.7:
                try:
                    # owner of refund-bot is reviewer_a → use reviewer_b
                    owner_id = agent.owner_user_id
                    decider = reviewer_b if owner_id == reviewer_a.id else reviewer_a
                    if rng.random() < 0.6:
                        approve(db, ar.id, decider, "Historical seed approval – looks legitimate")
                    else:
                        reject(db, ar.id, decider, "Historical seed rejection – policy review")
                except Exception:
                    pass
            else:
                # leave a couple pending only if recent
                if (now - ts).total_seconds() > 3600:
                    ar.status = "approved"
                    ar.decision = "allow"
                    ar.decision_reason = "seed auto-closed stale pending"
        db.commit()
        created += 1

    console.print(f"[green]Created {created} historical action requests[/green]")


def func_count_actions(db):
    from sqlalchemy import func

    from app.models import ActionRequest

    return select(func.count()).select_from(ActionRequest)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed AgentWarden demo data")
    parser.add_argument("--reset", action="store_true", help="Wipe and reseed")
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
    try:
        ledger.ensure_genesis(db)
        db.commit()

        if args.reset:
            reset_db(db)

        console.print("[bold]Seeding AgentWarden…[/bold]")
        users = seed_users(db)
        console.print(f"  Users: {len(users)}")
        agents = seed_agents(db, users)
        console.print(f"  Agents: {list(agents.keys())}")
        for name, (agent, key) in agents.items():
            if key:
                console.print(f"    [cyan]{name}[/cyan] API key: [bold]{key}[/bold]")
        policy = seed_policy(db, users["admin@demo.local"])
        console.print(f"  Policy v{policy.version} active")
        seed_history(db, agents, n=50)

        console.print("\n[bold green]Seed complete.[/bold green]")
        console.print("Demo logins:")
        console.print("  admin@demo.local / demo-admin-pass")
        console.print("  reviewer_a@demo.local / demo-reviewer-pass")
        console.print("  reviewer_b@demo.local / demo-reviewer-pass")
        console.print("  auditor@demo.local / demo-auditor-pass")
    finally:
        db.close()


if __name__ == "__main__":
    main()
