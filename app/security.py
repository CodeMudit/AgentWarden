"""Password hashing, API key auth, sessions, CSRF, RBAC dependencies."""

from __future__ import annotations

import hashlib
import secrets
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, Header, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import Agent, User

ph = PasswordHasher()

class RedirectToLogin(Exception):
    """Raised when a web route requires auth."""


SESSION_COOKIE = "aw_session"
CSRF_COOKIE = "aw_csrf"
SESSION_MAX_AGE = 60 * 60 * 12  # 12 hours


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


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().secret_key, salt="agentwarden-session")


def create_session_token(user_id: int) -> str:
    return _serializer().dumps({"uid": user_id})


def read_session_token(token: str) -> int | None:
    try:
        data = _serializer().loads(token, max_age=SESSION_MAX_AGE)
        return int(data["uid"])
    except (BadSignature, SignatureExpired, KeyError, TypeError, ValueError):
        return None


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def get_user_by_id(db: Session, user_id: int) -> User | None:
    return db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    uid = read_session_token(token)
    if uid is None:
        return None
    user = get_user_by_id(db, uid)
    if user is None or not user.is_active:
        return None
    return user


def require_web_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = get_current_user(request, db)
    if user is None:
        raise RedirectToLogin()
    return user


def require_web_role(roles: list[str]):
    def _dep(request: Request, db: Session = Depends(get_db)) -> User:
        user = require_web_user(request, db)
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return _dep


def verify_csrf(request: Request, form_token: str | None = None) -> None:
    """Validate CSRF token from form field or X-CSRF-Token header against cookie."""
    cookie_token = request.cookies.get(CSRF_COOKIE)
    header_token = request.headers.get("X-CSRF-Token")
    token = form_token or header_token
    if not cookie_token or not token or not secrets.compare_digest(cookie_token, token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": {"code": "csrf_failed", "message": "CSRF validation failed"}},
        )


# --- Phase 1 header-based human auth (kept for API tests) ---


def require_user_role(
    roles: list[str],
    x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None,
    db: Session = Depends(get_db),
) -> User:
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
        ) from None
    user = get_user_by_id(db, uid)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "unauthorized", "message": "User not found or inactive"}},
        )
    if user.role not in roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": {"code": "forbidden", "message": f"Role {user.role} not in {roles}"}},
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
