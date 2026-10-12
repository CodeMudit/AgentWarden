"""Incident and accountability chain API endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Incident, User
from app.schemas import IncidentCreateIn, IncidentOut, IncidentResolveIn
from app.security import (
    require_admin,
    require_reviewer_or_admin,
    require_session_role,
    require_session_user,
)
from app.services import incidents as incidents_svc
from app.services.incidents import IncidentError

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    user: User = Depends(require_session_user),
    db: Session = Depends(get_db),
):
    """List all governance incidents. Auditors have read-only access."""
    rows = list(db.execute(select(Incident).order_by(Incident.created_at.desc())).scalars().all())
    return [IncidentOut.model_validate(inc) for inc in rows]


@router.post("", response_model=IncidentOut, status_code=201)
def create_incident(
    body: IncidentCreateIn,
    user: User = Depends(require_reviewer_or_admin),
    db: Session = Depends(get_db),
):
    try:
        inc = incidents_svc.open_incident(
            db,
            title=body.title,
            description=body.description,
            creator_user=user,
            agent_id=body.agent_id,
            action_request_id=body.action_request_id,
            severity=body.severity,
            assigned_user_id=body.assigned_user_id,
        )
        db.commit()
        db.refresh(inc)
        return IncidentOut.model_validate(inc)
    except IncidentError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": e.code, "message": e.message}},
        )


@router.get("/{incident_id}/chain")
def get_incident_accountability_chain(
    incident_id: int,
    user: User = Depends(require_session_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve full end-to-end accountability chain for an incident."""
    inc = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
    if inc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "not_found", "message": "Incident not found"}},
        )
    return incidents_svc.get_accountability_chain(db, inc)


@router.post("/{incident_id}/resolve", response_model=IncidentOut)
def resolve_incident(
    incident_id: int,
    body: IncidentResolveIn,
    user: User = Depends(require_reviewer_or_admin),
    db: Session = Depends(get_db),
):
    try:
        inc = incidents_svc.resolve_incident(
            db,
            incident_id=incident_id,
            user=user,
            resolution_notes=body.resolution_notes,
        )
        db.commit()
        db.refresh(inc)
        return IncidentOut.model_validate(inc)
    except IncidentError as e:
        code = status.HTTP_404_NOT_FOUND if e.code == "not_found" else status.HTTP_400_BAD_REQUEST
        raise HTTPException(
            status_code=code,
            detail={"error": {"code": e.code, "message": e.message}},
        )
