"""Parameter-bound approvals: TOCTOU defence via params_hash."""

from __future__ import annotations

from app.services.actions import compute_params_hash


def _headers_agent(api_key: str):
    return {"X-API-Key": api_key}


def test_compute_params_hash_stable():
    a = compute_params_hash({"amount": 900, "currency": "USD"})
    b = compute_params_hash({"currency": "USD", "amount": 900})
    assert a == b
    assert len(a) == 64
    # Different values → different hash
    c = compute_params_hash({"amount": 9000, "currency": "USD"})
    assert a != c


def test_request_stores_params_hash(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    agent, key = agent_with_key
    r = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 40}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    assert r.status_code == 200
    action_id = r.json()["id"]

    from sqlalchemy import select

    from app.models import ActionRequest

    ar = db.execute(select(ActionRequest).where(ActionRequest.id == action_id)).scalar_one()
    assert ar.params_hash is not None
    assert ar.params_hash == compute_params_hash({"amount": 40})


def test_complete_with_matching_params(
    client, db, admin_user, reviewer_a, agent_with_key, active_policy
):
    agent, key = agent_with_key
    r = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 40}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    assert r.status_code == 200
    action_id = r.json()["id"]
    assert r.json()["decision"] == "allow"

    r2 = client.post(
        f"/v1/actions/{action_id}/complete",
        json={
            "success": True,
            "result": {"refund_id": "r-1"},
            "execution_params": {"amount": 40},
        },
        headers=_headers_agent(key),
    )
    assert r2.status_code == 200
    assert r2.json()["status"] == "completed"


def test_complete_with_tampered_params_blocked(
    client, db, admin_user, reviewer_a, reviewer_b, agent_with_key, active_policy
):
    """Approved $900 refund cannot execute as $9000."""
    from tests.conftest import login_as

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

    login_as(client, reviewer_b)
    r_ap = client.post(
        f"/v1/approvals/{action_id}/approve",
        json={"reason": "Legitimate high-value refund for VIP customer"},
    )
    assert r_ap.status_code == 200

    # Tamper: try to complete with $9000
    r2 = client.post(
        f"/v1/actions/{action_id}/complete",
        json={
            "success": True,
            "result": {"refund_id": "r-evil"},
            "execution_params": {"amount": 9000},
        },
        headers=_headers_agent(key),
    )
    assert r2.status_code == 400
    body = r2.json()
    err = body.get("detail", {}).get("error", {}) or body.get("error", {})
    assert err.get("code") == "param_mismatch"
    assert "params_hash mismatch" in err.get("message", "")

    # Action must still be approved (not completed)
    from sqlalchemy import select

    from app.models import ActionRequest, LedgerEntry

    db.expire_all()
    ar = db.execute(select(ActionRequest).where(ActionRequest.id == action_id)).scalar_one()
    assert ar.status == "approved"

    # Ledger has param_mismatch_blocked
    events = list(
        db.execute(
            select(LedgerEntry).where(LedgerEntry.event_type == "param_mismatch_blocked")
        ).scalars()
    )
    assert len(events) >= 1
    payload = events[-1].payload
    assert payload["expected_hash"] == ar.params_hash
    assert payload["got_hash"] != ar.params_hash


def test_complete_without_execution_params_still_works(
    client, db, admin_user, reviewer_a, agent_with_key, active_policy
):
    """Back-compat: omitting execution_params does not block completion."""
    agent, key = agent_with_key
    r = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 40}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    action_id = r.json()["id"]
    r2 = client.post(
        f"/v1/actions/{action_id}/complete",
        json={"success": True, "result": {}},
        headers=_headers_agent(key),
    )
    assert r2.status_code == 200
    assert r2.json()["status"] == "completed"
