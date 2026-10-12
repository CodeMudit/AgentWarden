"""Tests for Incident service, human accountability chain, and ledger tracking."""

from __future__ import annotations

import pytest

from app.models import ActionRequest, Incident, User
from app.services.incidents import (
    IncidentError,
    get_accountability_chain,
    get_incident_metrics,
    open_incident,
    resolve_incident,
)


def test_incident_lifecycle_and_accountability_chain(db, admin_user, reviewer_a, agent_with_key):
    agent, _ = agent_with_key

    # 1. Create an ActionRequest representing a suspicious activity
    ar = ActionRequest(
        agent_id=agent.id,
        tool="issue_refund",
        params={"amount": 950},
        sensitivity="internal",
        decision="deny",
        status="denied",
        reason="Suspicious high-value refund pattern",
    )
    db.add(ar)
    db.flush()

    # 2. Open an incident referencing the agent and action
    inc = open_incident(
        db,
        title="High Value Refund Anomaly",
        description="Agent attempted refund exceeding single-session threshold.",
        creator_user=admin_user,
        agent_id=agent.id,
        action_request_id=ar.id,
        severity="high",
        assigned_user_id=reviewer_a.id,
    )
    db.commit()

    assert inc.id is not None
    assert inc.status == "open"
    assert inc.severity == "high"

    # 3. Retrieve accountability chain by ID and by Incident object
    chain_by_id = get_accountability_chain(db, inc.id)
    assert chain_by_id is not None
    assert chain_by_id["agent"]["name"] == agent.name
    assert chain_by_id["owner"]["id"] == reviewer_a.id  # reviewer_a owns refund-bot
    assert chain_by_id["action"]["id"] == ar.id
    assert "ledger_trail" in chain_by_id

    chain_by_obj = get_accountability_chain(db, inc)
    assert chain_by_obj is not None
    assert chain_by_obj["incident"]["id"] == inc.id

    # 4. Resolve incident with valid notes
    resolved = resolve_incident(
        db,
        incident=inc,
        user=reviewer_a,
        resolution_notes="Investigated with financial auditor. Policy thresholds updated and agent restored.",
    )
    db.commit()

    assert resolved.status == "resolved"
    assert resolved.resolved_at is not None
    assert "auditor" in resolved.resolution_notes

    # 5. Check incident metrics
    metrics = get_incident_metrics(db)
    assert metrics["total"] >= 1
    assert metrics["resolved"] >= 1


def test_resolve_incident_requires_10_characters(db, admin_user):
    inc = open_incident(
        db,
        title="Minor discrepancy",
        description="Testing resolution note length check",
        creator_user=admin_user,
        severity="low",
    )
    db.commit()

    with pytest.raises((IncidentError, ValueError)):
        resolve_incident(db, incident=inc, user=admin_user, resolution_notes="too short")
