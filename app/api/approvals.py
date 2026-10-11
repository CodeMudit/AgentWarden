"""Human approval endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.schemas import ActionStatusOut, ApprovalIn
from app.security import require_reviewer_or_admin
from app.services.approvals import ApprovalError, approve, reject

router = APIRouter(prefix="/approvals", tags=["approvals"])


@router.post("/{action_id}/approve", response_model=ActionStatusOut)
def approve_action(
    action_id: int,
    body: ApprovalIn,
    user: User = Depends(require_reviewer_or_admin),
    db: Session = Depends(get_db),
):
    try:
        ar = approve(db, action_id, user, body.reason)
        db.commit()
        db.refresh(ar)
        return ActionStatusOut.model_validate(ar)
    except ApprovalError as e:
        code = status.HTTP_404_NOT_FOUND if e.code == "not_found" else status.HTTP_400_BAD_REQUEST
        if e.code == "separation_of_duties":
            code = status.HTTP_403_FORBIDDEN
        raise HTTPException(
            status_code=code,
            detail={"error": {"code": e.code, "message": e.message}},
        )


@router.post("/{action_id}/reject", response_model=ActionStatusOut)
def reject_action(
    action_id: int,
    body: ApprovalIn,
    user: User = Depends(require_reviewer_or_admin),
    db: Session = Depends(get_db),
):
    try:
        ar = reject(db, action_id, user, body.reason)
        db.commit()
        db.refresh(ar)
        return ActionStatusOut.model_validate(ar)
    except ApprovalError as e:
        code = status.HTTP_404_NOT_FOUND if e.code == "not_found" else status.HTTP_400_BAD_REQUEST
        if e.code == "separation_of_duties":
            code = status.HTTP_403_FORBIDDEN
        raise HTTPException(
            status_code=code,
            detail={"error": {"code": e.code, "message": e.message}},
        )
