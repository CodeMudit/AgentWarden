"""Tests for Work Allocation service, metrics, and human-vs-agent task routing."""

from __future__ import annotations

from app.models import ActionRequest, Agent, User, WorkItem
from app.services.work_allocation import (
    complete_work_item,
    get_allocation_metrics,
    route_work_item,
)


def test_work_allocation_confidence_and_risk(db, admin_user, reviewer_a, agent_with_key):
    agent, _ = agent_with_key

    # Low confidence (< 0.85) -> routes to human
    item_low = route_work_item(
        db,
        title="Handle Ambiguous Dispute",
        task_type="dispute_resolution",
        risk_category="medium",
        confidence_score=0.72,
        preferred_user_id=reviewer_a.id,
    )
    db.commit()

    assert item_low.assignee_type == "human"
    assert item_low.assignee_id == str(reviewer_a.id)
    assert item_low.confidence_score == 0.72
    assert "low confidence" in item_low.routing_reason

    # High or critical risk -> routes to human
    item_high_risk = route_work_item(
        db,
        title="High Value Transfer Approval",
        task_type="wire_transfer",
        risk_category="critical",
        confidence_score=0.98,
        preferred_user_id=reviewer_a.id,
    )
    db.commit()

    assert item_high_risk.assignee_type == "human"
    assert "high risk" in item_high_risk.routing_reason

    # High confidence (>= 0.85) and medium/low risk -> routes to AI agent
    item_agent = route_work_item(
        db,
        title="Routine Order Lookup",
        task_type="read_status",
        risk_category="low",
        confidence_score=0.96,
        preferred_agent_id=agent.id,
    )
    db.commit()

    assert item_agent.assignee_type == "agent"
    assert item_agent.assignee_id == str(agent.id)
    assert "AI agent" in item_agent.routing_reason


def test_work_item_completion(db, agent_with_key):
    agent, _ = agent_with_key
    item = route_work_item(
        db,
        title="Check status task",
        task_type="status_check",
        risk_category="low",
        confidence_score=0.92,
        preferred_agent_id=agent.id,
    )
    db.commit()

    completed = complete_work_item(
        db,
        item_id=item.id,
        status="completed",
        resolution_notes="Task processed successfully within 120ms.",
    )
    db.commit()

    assert completed.status == "completed"
    assert completed.completed_at is not None
    assert "processed successfully" in completed.notes


def test_work_allocation_metrics(db, agent_with_key):
    metrics = get_allocation_metrics(db)
    assert "total" in metrics
    assert "human_count" in metrics
    assert "agent_count" in metrics
    assert "human_pct" in metrics
    assert "agent_pct" in metrics
    assert "human_allocated_pct" in metrics
    assert "agent_allocated_pct" in metrics
    assert isinstance(metrics["human_allocated_pct"], float)
    assert isinstance(metrics["agent_allocated_pct"], float)
