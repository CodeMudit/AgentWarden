"""End-to-end workflow: allow/deny/pending, approvals, separation of duties, kill switch."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.services.escalation import escalate_overdue


def _headers_agent(api_key: str):
    return {"X-API-Key": api_key}


def _headers_user(user_id: int):
    return {"X-User-Id": str(user_id)}


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_allow_path(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    agent, key = agent_with_key
    r = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 40}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    assert r.status_code == 200
    data = r.json()
    assert data["decision"] == "allow"
    assert data["matched_rule_id"] == "refund-small-auto"


def test_deny_pii_email(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    agent, key = agent_with_key
    r = client.post(
        "/v1/actions/request",
        json={
            "tool": "send_email",
            "params": {"to": "leak@gmail.com", "subject": "Customer Export"},
            "sensitivity": "pii",
        },
        headers=_headers_agent(key),
    )
    assert r.status_code == 200
    data = r.json()
    assert data["decision"] == "deny"
    assert data["matched_rule_id"] == "block-external-pii"


def test_require_approval_and_approve(
    client, db, admin_user, reviewer_a, reviewer_b, agent_with_key, active_policy
):
    agent, key = agent_with_key
    r = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 900}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    assert r.status_code == 200
    data = r.json()
    assert data["decision"] == "require_approval"
    action_id = data["id"]

    # Owner (reviewer_a) blocked
    r2 = client.post(
        f"/v1/approvals/{action_id}/approve",
        json={"reason": "I am the owner trying to approve this"},
        headers=_headers_user(reviewer_a.id),
    )
    assert r2.status_code == 403
    assert r2.json()["detail"]["error"]["code"] == "separation_of_duties"

    # Other reviewer can approve
    r3 = client.post(
        f"/v1/approvals/{action_id}/approve",
        json={"reason": "Looks legitimate after manual review"},
        headers=_headers_user(reviewer_b.id),
    )
    assert r3.status_code == 200
    assert r3.json()["status"] == "approved"

    # Double decision blocked
    r4 = client.post(
        f"/v1/approvals/{action_id}/approve",
        json={"reason": "Trying to decide again after already decided"},
        headers=_headers_user(reviewer_b.id),
    )
    assert r4.status_code == 400

    # Agent can complete
    r5 = client.post(
        f"/v1/actions/{action_id}/complete",
        json={"success": True, "result": {"refund_id": "R-1"}},
        headers=_headers_agent(key),
    )
    assert r5.status_code == 200
    assert r5.json()["status"] == "completed"


def test_reject(client, db, admin_user, reviewer_a, reviewer_b, agent_with_key, active_policy):
    agent, key = agent_with_key
    r = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 500}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    action_id = r.json()["id"]
    r2 = client.post(
        f"/v1/approvals/{action_id}/reject",
        json={"reason": "Suspicious amount, rejecting this request"},
        headers=_headers_user(reviewer_b.id),
    )
    assert r2.status_code == 200
    assert r2.json()["status"] == "rejected"


def test_approval_reason_min_length(
    client, db, admin_user, reviewer_a, reviewer_b, agent_with_key, active_policy
):
    agent, key = agent_with_key
    r = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 200}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    action_id = r.json()["id"]
    r2 = client.post(
        f"/v1/approvals/{action_id}/approve",
        json={"reason": "short"},
        headers=_headers_user(reviewer_b.id),
    )
    assert r2.status_code == 422


def test_missing_api_key(client):
    r = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 10}, "sensitivity": "internal"},
    )
    assert r.status_code == 401


def test_invalid_api_key(client):
    r = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 10}, "sensitivity": "internal"},
        headers={"X-API-Key": "aw_bogus"},
    )
    assert r.status_code == 401


def test_kill_switch_agent(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    agent, key = agent_with_key
    r = client.post(
        f"/v1/agents/{agent.id}/suspend",
        headers=_headers_user(admin_user.id),
    )
    assert r.status_code == 200
    assert r.json()["status"] == "suspended"

    r2 = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 10}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    assert r2.json()["decision"] == "deny"
    assert "suspended" in (r2.json()["reason"] or "").lower()


def test_system_freeze(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    agent, key = agent_with_key
    r = client.post(
        "/v1/system/freeze",
        json={"note": "maintenance"},
        headers=_headers_user(admin_user.id),
    )
    assert r.status_code == 200
    assert r.json()["is_frozen"] is True

    r2 = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 10}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    assert r2.json()["decision"] == "deny"
    assert "frozen" in (r2.json()["reason"] or "").lower()

    client.post("/v1/system/unfreeze", headers=_headers_user(admin_user.id))


def test_escalation(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    agent, key = agent_with_key
    from app.services import actions as actions_svc

    ar = actions_svc.request_action(
        db,
        agent=agent,
        tool="issue_refund",
        params={"amount": 300},
        sensitivity="internal",
        sla_override_seconds=1,
    )
    # Force deadline into the past
    ar.sla_deadline = datetime.now(UTC) - timedelta(seconds=10)
    db.commit()

    n = escalate_overdue(db)
    assert n >= 1
    db.refresh(ar)
    assert ar.status == "escalated"


def test_rate_limit_via_api(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    agent, key = agent_with_key
    decisions = []
    for i in range(7):
        r = client.post(
            "/v1/actions/request",
            json={"tool": "issue_refund", "params": {"amount": 5}, "sensitivity": "internal"},
            headers=_headers_agent(key),
        )
        decisions.append(r.json()["decision"])
    # First few allow (under rate limit of 5), later deny
    assert "allow" in decisions
    assert "deny" in decisions


def test_policy_simulate(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    agent, key = agent_with_key
    # Generate some history
    for amount in [40, 200, 50]:
        client.post(
            "/v1/actions/request",
            json={"tool": "issue_refund", "params": {"amount": amount}, "sensitivity": "internal"},
            headers=_headers_agent(key),
        )
    draft = {
        "default_effect": "deny",
        "rules": [
            {
                "id": "allow-all-refunds",
                "priority": 1,
                "match": {"tools": ["issue_refund"]},
                "conditions": [],
                "effect": "allow",
            }
        ],
    }
    r = client.post(
        "/v1/policies/simulate",
        json={"rules": draft, "last_n": 20},
        headers=_headers_user(admin_user.id),
    )
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 1
    assert "newly_allowed" in data


def test_ledger_verify_api(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    agent, key = agent_with_key
    client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 10}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    r = client.post("/v1/ledger/verify", headers=_headers_user(admin_user.id))
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_create_agent_and_policy(client, db, admin_user, reviewer_a):
    r = client.post(
        "/v1/agents",
        json={
            "name": "email-assistant",
            "purpose": "Sends email",
            "owner_user_id": reviewer_a.id,
            "risk_tier": "high",
        },
        headers=_headers_user(admin_user.id),
    )
    assert r.status_code == 201
    assert "api_key" in r.json()
    assert r.json()["api_key"].startswith("aw_")

    rules = {"default_effect": "deny", "rules": []}
    r2 = client.post(
        "/v1/policies",
        json={"rules": rules, "note": "empty"},
        headers=_headers_user(admin_user.id),
    )
    assert r2.status_code == 201
    pid = r2.json()["id"]
    r3 = client.post(
        f"/v1/policies/{pid}/activate",
        headers=_headers_user(admin_user.id),
    )
    assert r3.status_code == 200
    assert r3.json()["is_active"] is True
