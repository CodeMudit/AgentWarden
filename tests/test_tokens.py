"""Decision token: issue, verify, tamper, expiry, replay, wrong params/tool."""

from __future__ import annotations

from app.tokens import verify_token_offline


def _headers_agent(api_key: str):
    return {"X-API-Key": api_key}


def test_allow_issues_token(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    agent, key = agent_with_key
    r = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 40}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    assert r.status_code == 200
    data = r.json()
    assert data["decision"] == "allow"
    assert data.get("decision_token")
    token = data["decision_token"]
    assert "." in token


def test_verify_consumes_token(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    agent, key = agent_with_key
    r = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 40}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    token = r.json()["decision_token"]

    r2 = client.post("/v1/tokens/verify", json={"token": token, "tool": "issue_refund"})
    assert r2.status_code == 200
    body = r2.json()
    assert body["valid"] is True
    assert body["claims"]["tool"] == "issue_refund"

    # Replay blocked
    r3 = client.post("/v1/tokens/verify", json={"token": token, "tool": "issue_refund"})
    assert r3.status_code == 200
    assert r3.json()["valid"] is False
    assert "replay" in r3.json()["reason"].lower() or "consumed" in r3.json()["reason"].lower()


def test_tampered_token_rejected(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    agent, key = agent_with_key
    r = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 40}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    token = r.json()["decision_token"]
    # Flip one character in the signature part
    parts = token.split(".")
    sig = parts[1]
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    bad = parts[0] + "." + flipped

    r2 = client.post("/v1/tokens/verify", json={"token": bad})
    assert r2.status_code == 200
    assert r2.json()["valid"] is False


def test_wrong_tool_rejected(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    agent, key = agent_with_key
    r = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 40}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    token = r.json()["decision_token"]
    r2 = client.post("/v1/tokens/verify", json={"token": token, "tool": "send_email"})
    assert r2.status_code == 200
    assert r2.json()["valid"] is False
    assert "tool" in r2.json()["reason"].lower()


def test_well_known_keys(client):
    r = client.get("/v1/.well-known/keys")
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data
    assert data["keys"][0]["crv"] == "Ed25519"
    assert data["keys"][0]["kty"] == "OKP"


def test_offline_verify(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    from app.tokens import get_public_key_raw

    agent, key = agent_with_key
    r = client.post(
        "/v1/actions/request",
        json={"tool": "issue_refund", "params": {"amount": 40}, "sensitivity": "internal"},
        headers=_headers_agent(key),
    )
    token = r.json()["decision_token"]
    result = verify_token_offline(token, get_public_key_raw())
    assert result.valid is True
    assert result.claims["tool"] == "issue_refund"


def test_deny_does_not_issue_token(client, db, admin_user, reviewer_a, agent_with_key, active_policy):
    agent, key = agent_with_key
    r = client.post(
        "/v1/actions/request",
        json={
            "tool": "send_email",
            "params": {"to": "leak@gmail.com", "subject": "x"},
            "sensitivity": "pii",
        },
        headers=_headers_agent(key),
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "deny"
    assert r.json().get("decision_token") is None
