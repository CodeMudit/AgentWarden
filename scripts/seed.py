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
from app.models import (
    ActionRequest,
    Agent,
    DecisionToken,
    ExceptionCase,
    Incident,
    LedgerEntry,
    LedgerHead,
    Policy,
    SystemState,
    User,
    WorkItem,
)
from app.security import generate_api_key, hash_password
from app.services import actions as actions_svc
from app.services.work_allocation import route_work_item

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
            "id": "block-restricted-pii-scope",
            "priority": 4,
            "description": "Block actions attempting to touch restricted PII data scopes",
            "conditions": [
                {"type": "data_scope_in", "value": ["restricted:ssn", "restricted:cc_number"]},
            ],
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
        {
            "id": "sql-analytics-allow",
            "priority": 12,
            "match": {"agents": ["sql-analytics-agent"], "tools": ["run_readonly_query", "export_csv"]},
            "conditions": [],
            "effect": "allow",
        },
        {
            "id": "remediation-critical-review",
            "priority": 8,
            "match": {"agents": ["auto-remediation-bot"], "tools": ["rollback_deployment", "restart_service"]},
            "conditions": [],
            "effect": "require_approval",
        },
    ],
}


def reset_db(db) -> None:
    console.print("[yellow]Resetting all data…[/yellow]")
    for table in (
        Incident,
        ExceptionCase,
        WorkItem,
        DecisionToken,
        ActionRequest,
        LedgerEntry,
        Agent,
        Policy,
        User,
        SystemState,
        LedgerHead,
    ):
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
        (
            "refund-bot",
            "Issues and validates customer order refunds within authorized limits",
            users["reviewer_a@demo.local"].id,
            "medium",
            ["issue_refund", "send_email", "lookup_order", "check_order_status"],
            ["orders:read", "refunds:write", "internal"],
            0.05,
        ),
        (
            "email-assistant",
            "Drafts and sends customer correspondence and team updates",
            users["reviewer_b@demo.local"].id,
            "high",
            ["send_email", "fetch_inbox", "search_contacts"],
            ["company.com", "internal"],
            0.02,
        ),
        (
            "sql-analytics-agent",
            "Executes read-only operational and financial reporting queries",
            users["admin@demo.local"].id,
            "low",
            ["run_readonly_query", "export_csv"],
            ["analytics_db:read", "reporting"],
            0.01,
        ),
        (
            "auto-remediation-bot",
            "Automated infrastructure recovery and rollbacks upon incident alerts",
            users["admin2@demo.local"].id,
            "critical",
            ["restart_service", "rollback_deployment", "flush_cache"],
            ["prod_infra", "restricted"],
            0.15,
        ),
    ]
    for name, purpose, owner_id, risk_cat, permitted, data_scopes, cost in specs:
        existing = db.execute(select(Agent).where(Agent.name == name)).scalar_one_or_none()
        if existing:
            result[name] = (existing, None)
            continue
        full, prefix, key_hash = generate_api_key()
        agent = Agent(
            name=name,
            purpose=purpose,
            owner_user_id=owner_id,
            risk_category=risk_cat,
            risk_tier=risk_cat,
            permitted_actions=permitted,
            data_access=data_scopes,
            cost_per_call=cost,
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
            payload={
                "name": name,
                "risk_category": risk_cat,
                "permitted_actions": permitted,
                "data_access": data_scopes,
            },
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
        note="Demo seed policy with PS5 governance data scopes",
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
    sql_bot = agents.get("sql-analytics-agent", (None, None))[0]
    now = datetime.now(UTC)
    rng = random.Random(42)

    scenarios = []
    for i in range(n):
        roll = rng.random()
        ts = now - timedelta(hours=rng.randint(1, 168), minutes=rng.randint(0, 59))
        if roll < 0.40:
            amount = rng.choice([10, 25, 40, 50, 75, 90, 100])
            scenarios.append(
                (
                    refund_bot,
                    "issue_refund",
                    {"amount": amount, "order_id": f"ORD-{1000 + i}"},
                    "internal",
                    ["orders:read", "refunds:write"],
                    ts,
                )
            )
        elif roll < 0.60:
            amount = rng.choice([150, 200, 350, 500, 900, 1200])
            scenarios.append(
                (
                    refund_bot,
                    "issue_refund",
                    {"amount": amount, "order_id": f"ORD-{2000 + i}"},
                    "internal",
                    ["orders:read", "refunds:write"],
                    ts,
                )
            )
        elif roll < 0.75:
            scenarios.append(
                (
                    email_bot,
                    "send_email",
                    {"to": "customer@gmail.com", "subject": "Customer Export"},
                    "pii",
                    ["customer_db:read"],
                    ts,
                )
            )
        elif roll < 0.90:
            scenarios.append(
                (
                    email_bot,
                    "send_email",
                    {"to": "alice@company.com", "subject": f"Weekly Status {i}"},
                    "internal",
                    ["company.com"],
                    ts,
                )
            )
        elif sql_bot:
            scenarios.append(
                (
                    sql_bot,
                    "run_readonly_query",
                    {"query": "SELECT count(*) FROM orders WHERE status = 'delivered'"},
                    "internal",
                    ["analytics_db:read", "reporting"],
                    ts,
                )
            )

    scenarios.sort(key=lambda x: x[5])

    from app.models import User as UserModel
    from app.services.approvals import approve, reject

    reviewer_b = db.execute(
        select(UserModel).where(UserModel.email == "reviewer_b@demo.local")
    ).scalar_one()
    reviewer_a = db.execute(
        select(UserModel).where(UserModel.email == "reviewer_a@demo.local")
    ).scalar_one()

    created = 0
    for agent, tool, params, sensitivity, data_used, ts in scenarios:
        ar = actions_svc.request_action(
            db,
            agent=agent,
            tool=tool,
            params=params,
            sensitivity=sensitivity,
            data_used=data_used,
        )
        ar.created_at = ts
        if ar.status == "pending":
            if rng.random() < 0.7:
                try:
                    owner_id = agent.owner_user_id
                    decider = reviewer_b if owner_id == reviewer_a.id else reviewer_a
                    if rng.random() < 0.6:
                        approve(db, ar.id, decider, "Historical seed approval – verified customer request")
                    else:
                        reject(db, ar.id, decider, "Historical seed rejection – policy review")
                except Exception:
                    pass
            else:
                if (now - ts).total_seconds() > 3600:
                    ar.status = "approved"
                    ar.decision = "allow"
                    ar.decision_reason = "seed auto-closed stale pending"
        db.commit()
        created += 1

    console.print(f"[green]Created {created} historical action requests[/green]")


def seed_work_allocation_and_incidents(db, users: dict[str, User], agents: dict[str, tuple[Agent, str | None]]) -> None:
    """Seed work items (human-vs-agent allocation) and sample incidents."""
    refund_bot = agents["refund-bot"][0]
    email_bot = agents["email-assistant"][0]
    reviewer_a = users["reviewer_a@demo.local"]
    reviewer_b = users["reviewer_b@demo.local"]

    # Seed 10 work items using route_task
    task_specs = [
        ("Process small return $15", "refunds", "low", 0.96, refund_bot.id),
        ("Verify damaged item photo", "refunds", "medium", 0.88, refund_bot.id),
        ("High-value claim $3,200", "refunds", "critical", 0.52, refund_bot.id),
        ("VIP corporate refund request", "refunds", "high", 0.61, refund_bot.id),
        ("Standard invoice lookup", "operations", "low", 0.98, refund_bot.id),
        ("Draft standard thank-you email", "communications", "low", 0.94, email_bot.id),
        ("Legal compliance notice draft", "communications", "critical", 0.45, email_bot.id),
        ("GDPR erasure request processing", "compliance", "critical", 0.38, None),
        ("Routine inventory reconciliation", "operations", "low", 0.92, None),
        ("Suspicious chargeback dispute", "fraud", "high", 0.58, refund_bot.id),
    ]

    for title, task_type, risk, confidence, agent_id in task_specs:
        route_work_item(
            db,
            title=title,
            task_type=task_type,
            risk_category=risk,
            confidence_score=confidence,
            preferred_agent_id=agent_id,
            preferred_user_id=reviewer_b.id if risk in ("high", "critical") else None,
        )

    # Seed 1 resolved incident for audit proof
    inc = Incident(
        title="Unauthorized SSN Data Field Access Attempt",
        description="Refund Bot attempted to read customer SSN and credit card numbers during refund lookup.",
        severity="high",
        status="resolved",
        agent_id=refund_bot.id,
        created_by_user_id=reviewer_a.id,
        assigned_user_id=reviewer_a.id,
        resolution_notes="Audited refund prompt templates. Enforced restricted PII block policy and re-verified agent data scope.",
        resolved_at=datetime.now(UTC),
    )
    db.add(inc)
    db.flush()

    ledger.append(
        db,
        event_type="incident_opened",
        actor_type="system",
        actor_id="breach_engine",
        subject_type="incident",
        subject_id=str(inc.id),
        payload={"title": inc.title, "agent_id": refund_bot.id, "severity": inc.severity},
    )
    ledger.append(
        db,
        event_type="incident_resolved",
        actor_type="user",
        actor_id=str(reviewer_a.id),
        subject_type="incident",
        subject_id=str(inc.id),
        payload={"resolution_notes": inc.resolution_notes},
    )
    db.commit()
    console.print("[green]Seeded work allocation tasks and accountability incident[/green]")


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
        seed_work_allocation_and_incidents(db, users, agents)

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
