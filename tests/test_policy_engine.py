"""Policy engine unit tests."""

from datetime import UTC, datetime

from app.policy.engine import RequestContext, evaluate, validate_policy

BASE_POLICY = {
    "default_effect": "deny",
    "rules": [
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
            "match": {"agents": ["refund-bot"], "tools": ["issue_refund"]},
            "conditions": [{"type": "amount_gt", "field": "amount", "value": 100}],
            "effect": "require_approval",
        },
        {
            "id": "block-external-pii",
            "priority": 5,
            "match": {"tools": ["send_email"]},
            "conditions": [
                {"type": "domain_not_in", "field": "to", "value": ["company.com"]},
                {"type": "sensitivity_in", "value": ["confidential", "pii"]},
            ],
            "effect": "deny",
        },
    ],
}


def test_default_deny():
    ctx = RequestContext(agent_name="other", tool="unknown", params={})
    d = evaluate(BASE_POLICY, ctx)
    assert d.effect == "deny"
    assert d.matched_rule_id is None


def test_amount_lte_allow():
    ctx = RequestContext(agent_name="refund-bot", tool="issue_refund", params={"amount": 40})
    d = evaluate(BASE_POLICY, ctx)
    assert d.effect == "allow"
    assert d.matched_rule_id == "refund-small-auto"


def test_amount_gt_require_approval():
    ctx = RequestContext(agent_name="refund-bot", tool="issue_refund", params={"amount": 900})
    d = evaluate(BASE_POLICY, ctx)
    assert d.effect == "require_approval"
    assert d.matched_rule_id == "refund-large-review"


def test_priority_ordering():
    # block-external-pii has priority 5 (lower = wins first)
    ctx = RequestContext(
        agent_name="email-assistant",
        tool="send_email",
        params={"to": "user@gmail.com"},
        sensitivity="pii",
    )
    d = evaluate(BASE_POLICY, ctx)
    assert d.effect == "deny"
    assert d.matched_rule_id == "block-external-pii"


def test_domain_in_allows_internal():
    policy = {
        "default_effect": "deny",
        "rules": [
            {
                "id": "internal-email",
                "priority": 10,
                "match": {"tools": ["send_email"]},
                "conditions": [{"type": "domain_in", "field": "to", "value": ["company.com"]}],
                "effect": "allow",
            }
        ],
    }
    ctx = RequestContext(
        agent_name="email-assistant",
        tool="send_email",
        params={"to": "alice@company.com"},
    )
    d = evaluate(policy, ctx)
    assert d.effect == "allow"


def test_rate_limit():
    policy = {
        "default_effect": "allow",
        "rules": [
            {
                "id": "rate",
                "priority": 1,
                "match": {"tools": ["issue_refund"]},
                "conditions": [{"type": "rate_limit", "value": {"max": 3, "window_seconds": 60}}],
                "effect": "deny",
            }
        ],
    }
    ctx = RequestContext(agent_name="refund-bot", tool="issue_refund", params={"amount": 1})
    # under limit
    d = evaluate(policy, ctx, history_counts={"refund-bot:issue_refund:60": 2})
    assert d.effect == "allow"
    # at/over limit
    d2 = evaluate(policy, ctx, history_counts={"refund-bot:issue_refund:60": 3})
    assert d2.effect == "deny"
    assert d2.matched_rule_id == "rate"


def test_param_matches():
    policy = {
        "default_effect": "deny",
        "rules": [
            {
                "id": "export",
                "priority": 1,
                "match": {"tools": ["send_email"]},
                "conditions": [
                    {"type": "param_matches", "field": "subject", "value": r"(?i)export"}
                ],
                "effect": "require_approval",
            }
        ],
    }
    ctx = RequestContext(
        agent_name="a",
        tool="send_email",
        params={"subject": "Customer Export Report"},
    )
    d = evaluate(policy, ctx)
    assert d.effect == "require_approval"


def test_time_window():
    policy = {
        "default_effect": "deny",
        "rules": [
            {
                "id": "biz-hours",
                "priority": 1,
                "match": {"tools": ["issue_refund"]},
                "conditions": [
                    {
                        "type": "time_window",
                        "value": {"hours": [9, 17], "weekdays": [0, 1, 2, 3, 4]},
                    }
                ],
                "effect": "allow",
            }
        ],
    }
    # Wednesday 10:00 UTC
    now = datetime(2026, 10, 7, 10, 0, tzinfo=UTC)
    ctx = RequestContext(agent_name="a", tool="issue_refund", params={}, now=now)
    d = evaluate(policy, ctx, now=now)
    assert d.effect == "allow"
    # Sunday
    now2 = datetime(2026, 10, 11, 10, 0, tzinfo=UTC)
    d2 = evaluate(policy, ctx, now=now2)
    assert d2.effect == "deny"


def test_validate_policy_rejects_bad():
    errors = validate_policy({"default_effect": "nope", "rules": []})
    assert any("default_effect" in e for e in errors)

    errors = validate_policy(
        {
            "default_effect": "deny",
            "rules": [
                {"id": "a", "priority": 1, "effect": "allow"},
                {"id": "a", "priority": 2, "effect": "deny"},
            ],
        }
    )
    assert any("duplicate" in e for e in errors)

    errors = validate_policy(
        {
            "default_effect": "deny",
            "rules": [
                {
                    "id": "bad",
                    "priority": 1,
                    "effect": "allow",
                    "conditions": [{"type": "not_a_real_type"}],
                }
            ],
        }
    )
    assert any("unknown type" in e for e in errors)


def test_validate_policy_ok():
    assert validate_policy(BASE_POLICY) == []


def test_evaluation_trace():
    ctx = RequestContext(
        agent_name="refund-bot", tool="issue_refund", params={"amount": 40}
    )
    d = evaluate(BASE_POLICY, ctx)
    assert d.effect == "allow"
    assert d.trace is not None
    assert any(s.get("matched") for s in d.trace)
    matched = next(s for s in d.trace if s.get("matched"))
    assert matched["rule_id"] == "refund-small-auto"
    assert matched["conditions"]
    assert all("holds" in c for c in matched["conditions"])
