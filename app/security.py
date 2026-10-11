"""Password hashing, API key auth, session helpers, RBAC dependencies."""

from __future__ import annotations

import hashlib
import secrets
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Agent, User

ph = PasswordHasher()


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def generate_api_key() -> tuple[str, str, str]:
    """Return (full_key, prefix, sha256_hash). Full key shown once."""
    raw = secrets.token_urlsafe(32)
    full = f"aw_{raw}"
    prefix = full[:12]
    key_hash = hashlib.sha256(full.encode("utf-8")).hexdigest()
    return full, prefix, key_hash


def hash_api_key(full_key: str) -> str:
    return hashlib.sha256(full_key.encode("utf-8")).hexdigest()


def get_agent_by_api_key(db: Session, api_key: str) -> Agent | None:
    if not api_key:
        return None
    key_hash = hash_api_key(api_key)
    return db.execute(select(Agent).where(Agent.api_key_hash == key_hash)).scalar_one_or_none()


def require_agent(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    db: Session = Depends(get_db),
) -> Agent:
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "missing_api_key", "message": "X-API-Key header required"}},
        )
    agent = get_agent_by_api_key(db, x_api_key)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "invalid_api_key", "message": "Invalid API key"}},
        )
    return agent


# Session-based human auth is fully wired in Phase 2.
# Phase 1 provides a simple header-based helper for tests and internal API use.


def get_user_by_id(db: Session, user_id: int) -> User | None:
    return db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()


def require_user_role(
    roles: list[str],
    x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None,
    db: Session = Depends(get_db),
) -> User:
    """Phase 1 human auth via X-User-Id header (replaced by sessions in Phase 2)."""
    if not x_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "unauthorized", "message": "X-User-Id required"}},
        )
    try:
        uid = int(x_user_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "unauthorized", "message": "Invalid user id"}},
        )
    user = get_user_by_id(db, uid)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "unauthorized", "message": "User not found or inactive"}},
        )
    if user.role not in roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": {
                    "code": "forbidden",
                    "message": f"Role {user.role} not in {roles}",
                }
            },
        )
    return user


def require_admin(
    x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None,
    db: Session = Depends(get_db),
) -> User:
    return require_user_role(["admin"], x_user_id, db)


def require_reviewer_or_admin(
    x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None,
    db: Session = Depends(get_db),
) -> User:
    return require_user_role(["admin", "reviewer"], x_user_id, db)
