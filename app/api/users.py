"""User management. Bootstrap is script-only (scripts/seed.py / bootstrap_admin.py)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.schemas import UserCreateIn, UserOut
from app.security import hash_password, require_admin

router = APIRouter(prefix="/users", tags=["users"])


@router.post("", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreateIn,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Create a user. Requires an authenticated admin session. No open bootstrap."""
    if body.role not in ("admin", "reviewer", "auditor"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": {
                    "code": "invalid_role",
                    "message": "role must be admin|reviewer|auditor",
                }
            },
        )
    existing = db.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": {"code": "conflict", "message": "email already registered"}},
        )
    user = User(
        email=body.email,
        name=body.name,
        password_hash=hash_password(body.password),
        role=body.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserOut.model_validate(user)


@router.get("", response_model=list[UserOut])
def list_users(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    rows = list(db.execute(select(User).order_by(User.id)).scalars().all())
    return [UserOut.model_validate(u) for u in rows]
