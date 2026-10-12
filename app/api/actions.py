"""Agent-facing action endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Agent
from app.schemas import ActionCompleteIn, ActionDecisionOut, ActionRequestIn, ActionStatusOut
from app.security import require_agent
from app.services import actions as actions_svc

router = APIRouter(prefix="/actions", tags=["actions"])


@router.post("/request", response_model=ActionDecisionOut)
def request_action(
    body: ActionRequestIn,
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
):
    ar = actions_svc.request_action(
        db,
        agent=agent,
        tool=body.tool,
        params=body.params,
        sensitivity=body.sensitivity,
        data_used=body.data_used,
        context=body.context,
    )
    db.commit()
    db.refresh(ar)

    token = getattr(ar, "_decision_token", None)
    if ar.decision == "require_approval":
        return ActionDecisionOut(
            id=ar.id,
            decision="require_approval",
            reason=ar.reason,
            matched_rule_id=ar.matched_rule_id,
            policy_version=ar.policy_version,
            status="pending",
            poll_url=f"/v1/actions/{ar.id}",
            decision_token=None,
        )
    return ActionDecisionOut(
        id=ar.id,
        decision=ar.decision or "deny",
        reason=ar.reason,
        matched_rule_id=ar.matched_rule_id,
        policy_version=ar.policy_version,
        status=ar.status,
        decision_token=token,
    )


@router.get("/{action_id}", response_model=ActionStatusOut)
def get_action(
    action_id: int,
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
):
    from sqlalchemy import select

    from app.models import ActionRequest

    ar = db.execute(select(ActionRequest).where(ActionRequest.id == action_id)).scalar_one_or_none()
    if ar is None or ar.agent_id != agent.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "not_found", "message": "Action not found"}},
        )
    return ActionStatusOut.model_validate(ar)


@router.post("/{action_id}/complete", response_model=ActionStatusOut)
def complete_action(
    action_id: int,
    body: ActionCompleteIn,
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
):
    try:
        ar = actions_svc.complete_action(
            db,
            agent,
            action_id,
            body.success,
            body.result,
            execution_params=body.execution_params,
        )
        db.commit()
        db.refresh(ar)
        return ActionStatusOut.model_validate(ar)
    except LookupError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "not_found", "message": "Action not found"}},
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": {"code": "forbidden", "message": str(e)}},
        )
    except ValueError as e:
        code = "param_mismatch" if "params_hash mismatch" in str(e) else "invalid_state"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": code, "message": str(e)}},
        )
