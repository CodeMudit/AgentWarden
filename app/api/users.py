"""Minimal user bootstrap for Phase 1 tests (full auth UI in Phase 2)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
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
    x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None,
):
    existing_users = list(db.execute(select(User)).scalars().all())
    if existing_users:
        if not x_user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": {"code": "unauthorized", "message": "X-User-Id required"}},
            )
        try:
            uid = int(x_user_id)
        except ValueError:
            raise HTTPException(
                status_code=401,
                detail={"error": {"code": "unauthorized", "message": "bad id"}},
            )
        admin = db.execute(select(User).where(User.id == uid)).scalar_one_or_none()
        if admin is None or admin.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": {"code": "forbidden", "message": "admin required"}},
            )

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
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    rows = list(db.execute(select(User).order_by(User.id)).scalars().all())
    return [UserOut.model_validate(u) for u in rows]
