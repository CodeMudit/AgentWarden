"""System freeze / unfreeze and internal helpers."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.schemas import FreezeIn
from app.security import require_admin
from app.services.killswitch import freeze_system, get_system_state, unfreeze_system

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/status")
def system_status(
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    state = get_system_state(db)
    return {
        "is_frozen": state.is_frozen,
        "frozen_by": state.frozen_by,
        "frozen_at": state.frozen_at.isoformat() if state.frozen_at else None,
        "note": state.note,
    }


@router.post("/freeze")
def freeze(
    body: FreezeIn,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    state = freeze_system(db, by=str(user.id), note=body.note)
    db.commit()
    return {
        "is_frozen": state.is_frozen,
        "frozen_by": state.frozen_by,
        "note": state.note,
    }


@router.post("/unfreeze")
def unfreeze(
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    state = unfreeze_system(db, by=str(user.id))
    db.commit()
    return {"is_frozen": state.is_frozen}
