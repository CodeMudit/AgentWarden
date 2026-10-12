"""Tests for unpermitted actions, data-used scope violations, auto-pause, and resume."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app import ledger
from app.models import Agent, ExceptionCase, Incident, Policy, User
from app.security import generate_api_key, hash_password
from app.services import actions as actions_svc
from app.services.killswitch import pause_agent, resume_agent


@pytest.fixture
def breach_env(db):
    admin = User(email="admin_breach@test.local", name="Admin", password_hash=hash_password("pw"), role="admin")
    reviewer = User(email="reviewer_breach@test.local", name="Reviewer", password_hash=hash_password("pw"), role="reviewer")
    db.add_all([admin, reviewer])
    db.flush()

    policy_doc = {
        "default_effect": "deny",
        "rules": [
            {
                "id": "allow-refund",
                "priority": 10,
                "match": {"agents": ["test-refund-agent"], "tools": ["issue_refund"]},
                "conditions": [{"type": "amount_lte", "field": "amount", "value": 100}],
                "effect": "allow",
            },
            {
                "id": "block-ssn",
                "priority": 5,
                "conditions": [{"type": "data_scope_in", "value": ["restricted:ssn"]}],
                "effect": "deny",
            },
        ],
    }
    p = Policy(version=1, rules=policy_doc, is_active=True, created_by=admin.id)
    db.add(p)
    db.flush()

    full_key, prefix, key_hash = generate_api_key()
    agent = Agent(
        name="test-refund-agent",
        purpose="Test Refund Agent",
        owner_user_id=reviewer.id,
        risk_category="medium",
        permitted_actions=["issue_refund", "lookup_order"],
        data_access=["orders:read", "refunds:write"],
        cost_per_call=0.05,
        status="active",
        api_key_prefix=prefix,
        api_key_hash=key_hash,
    )
    db.add(agent)
    db.flush()
    ledger.ensure_genesis(db)
    db.commit()

    return {"admin": admin, "reviewer": reviewer, "agent": agent, "policy": p, "api_key": full_key}


def test_unpermitted_action_triggers_breach_and_autopause(db, breach_env):
    agent = breach_env["agent"]

    # Agent attempts to call an action not in permitted_actions whitelist
    ar = actions_svc.request_action(
        db,
        agent=agent,
        tool="export_all_users",
        params={"format": "csv"},
        sensitivity="restricted",
    )
    db.commit()
    db.refresh(agent)

    # 1. Action was denied and flagged as breach
    assert ar.decision == "deny"
    assert ar.is_breach is True
    assert "not in permitted_actions" in (ar.reason or "")

    # 2. Agent was automatically paused
    assert agent.status == "paused"
    assert agent.breach_count == 1
    assert "not in permitted_actions" in (agent.status_reason or "")

    # 3. Incident was created
    inc = db.execute(
        select(Incident).where(Incident.agent_id == agent.id)
    ).scalar_one_or_none()
    assert inc is not None
    assert inc.status == "open"
    assert "automatically paused" in inc.title

    # 4. ExceptionCase was created
    exc = db.execute(
        select(ExceptionCase).where(ExceptionCase.agent_id == agent.id)
    ).scalar_one_or_none()
    assert exc is not None
    assert exc.status == "open"

    # 5. Subsequent allowed action is denied because agent is paused
    ar2 = actions_svc.request_action(
        db,
        agent=agent,
        tool="issue_refund",
        params={"amount": 25},
        sensitivity="internal",
    )
    db.commit()
    assert ar2.decision == "deny"
    assert "paused" in (ar2.reason or "").lower()


def test_unauthorized_data_scope_triggers_breach_and_autopause(db, breach_env):
    agent = breach_env["agent"]

    # Permitted tool 'issue_refund', but accesses data scope outside permitted data_access
    ar = actions_svc.request_action(
        db,
        agent=agent,
        tool="issue_refund",
        params={"amount": 20},
        sensitivity="internal",
        data_used=["credit_cards:full_pan"],
    )
    db.commit()
    db.refresh(agent)

    assert ar.decision == "deny"
    assert ar.is_breach is True
    assert "data scope" in (ar.reason or "").lower()
    assert agent.status == "paused"
    assert agent.breach_count >= 1


def test_policy_data_scope_condition_deny(db, breach_env):
    agent = breach_env["agent"]
    # Add restricted:ssn to agent data_access so agent whitelist passes, but policy rule 'block-ssn' catches it
    agent.data_access = ["orders:read", "refunds:write", "restricted:ssn"]
    db.commit()

    ar = actions_svc.request_action(
        db,
        agent=agent,
        tool="issue_refund",
        params={"amount": 50},
        sensitivity="internal",
        data_used=["restricted:ssn"],
    )
    db.commit()

    assert ar.decision == "deny"
    assert ar.matched_rule_id == "block-ssn"


def test_resume_agent_requires_admin_and_reason(db, breach_env):
    agent = breach_env["agent"]
    admin = breach_env["admin"]

    # Pause agent
    pause_agent(db, agent, admin.id, "Investigating anomaly")
    db.commit()
    db.refresh(agent)
    assert agent.status == "paused"

    # Resume with valid reason as admin
    resume_agent(db, agent, admin.id, "Investigation complete; guardrails confirmed")
    db.commit()
    db.refresh(agent)
    assert agent.status == "active"
    assert "Investigation complete" in (agent.status_reason or "")

    # Calling permitted tool now succeeds
    ar = actions_svc.request_action(
        db,
        agent=agent,
        tool="issue_refund",
        params={"amount": 25},
        sensitivity="internal",
        data_used=["orders:read"],
    )
    db.commit()
    assert ar.decision == "allow"
