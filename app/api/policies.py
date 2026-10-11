"""Policy list/create/activate/simulate."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger
from app.db import get_db
from app.models import Policy, User
from app.policy.engine import validate_policy
from app.policy.simulator import simulate
from app.schemas import (
    PolicyCreateIn,
    PolicyOut,
    PolicySimulateIn,
    PolicySimulateOut,
    SimulateChangedItem,
)
from app.security import require_admin, require_reviewer_or_admin

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("", response_model=list[PolicyOut])
def list_policies(
    user: User = Depends(require_reviewer_or_admin),
    db: Session = Depends(get_db),
):
    rows = list(db.execute(select(Policy).order_by(Policy.version.desc())).scalars().all())
    return [PolicyOut.model_validate(p) for p in rows]


@router.get("/active", response_model=PolicyOut | None)
def get_active(
    user: User = Depends(require_reviewer_or_admin),
    db: Session = Depends(get_db),
):
    p = db.execute(select(Policy).where(Policy.is_active.is_(True))).scalar_one_or_none()
    return PolicyOut.model_validate(p) if p else None


@router.post("", response_model=PolicyOut, status_code=201)
def create_policy(
    body: PolicyCreateIn,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    errors = validate_policy(body.rules)
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": {"code": "invalid_policy", "message": "; ".join(errors)}},
        )
    max_v = db.execute(select(Policy.version).order_by(Policy.version.desc()).limit(1)).scalar()
    version = (max_v or 0) + 1
    p = Policy(
        version=version,
        rules=body.rules,
        is_active=False,
        created_by=user.id,
        note=body.note,
    )
    db.add(p)
    db.flush()
    ledger.append(
        db,
        event_type="policy_created",
        actor_type="user",
        actor_id=str(user.id),
        subject_type="policy",
        subject_id=str(p.id),
        payload={"version": version, "note": body.note},
        policy_version=version,
    )
    db.commit()
    db.refresh(p)
    return PolicyOut.model_validate(p)


@router.post("/{policy_id}/activate", response_model=PolicyOut)
def activate_policy(
    policy_id: int,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    p = db.execute(select(Policy).where(Policy.id == policy_id)).scalar_one_or_none()
    if p is None:
        raise HTTPException(
            status_code=404, detail={"error": {"code": "not_found", "message": "Policy not found"}}
        )
    # Deactivate others
    for other in db.execute(select(Policy).where(Policy.is_active.is_(True))).scalars().all():
        other.is_active = False
    p.is_active = True
    ledger.append(
        db,
        event_type="policy_activated",
        actor_type="user",
        actor_id=str(user.id),
        subject_type="policy",
        subject_id=str(p.id),
        payload={"version": p.version},
        policy_version=p.version,
    )
    db.commit()
    db.refresh(p)
    return PolicyOut.model_validate(p)


@router.post("/simulate", response_model=PolicySimulateOut)
def simulate_policy(
    body: PolicySimulateIn,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    errors = validate_policy(body.rules)
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": {"code": "invalid_policy", "message": "; ".join(errors)}},
        )
    result = simulate(db, body.rules, last_n=body.last_n, since=body.since, until=body.until)
    return PolicySimulateOut(
        total=result["total"],
        unchanged=result["unchanged"],
        newly_allowed=result["newly_allowed"],
        newly_denied=result["newly_denied"],
        newly_require_approval=result["newly_require_approval"],
        changed=[SimulateChangedItem(**c) for c in result["changed"]],
    )
