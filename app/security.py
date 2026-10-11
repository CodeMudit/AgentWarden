"""Password hashing, API key auth, sessions, CSRF, RBAC dependencies.

Human JSON API and web UI authenticate via signed session cookies only.
X-User-Id is NOT accepted — it was a Phase-1 test shortcut and is removed
because it allowed forging any user's identity without credentials.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections import defaultdict
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

# Simple in-memory login rate limit: ip -> list of attempt timestamps
_login_attempts: dict[str, list[float]] = defaultdict(list)
LOGIN_WINDOW_SECONDS = 60
LOGIN_MAX_ATTEMPTS = 10


def check_login_rate_limit(client_ip: str) -> None:
    now = time.time()
    window_start = now - LOGIN_WINDOW_SECONDS
    attempts = [t for t in _login_attempts[client_ip] if t >= window_start]
    _login_attempts[client_ip] = attempts
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": {
                    "code": "rate_limited",
                    "message": "Too many login attempts. Try again in a minute.",
                }
            },
        )


def record_login_attempt(client_ip: str) -> None:
    _login_attempts[client_ip].append(time.time())


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


def _user_from_session(request: Request, db: Session) -> User | None:
    return get_current_user(request, db)


def require_session_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Require an authenticated human session (cookie). Used by JSON human API."""
    user = _user_from_session(request, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": "unauthorized",
                    "message": "Authentication required. Sign in via /login to obtain a session cookie.",
                }
            },
        )
    return user


def require_session_role(roles: list[str]):
    """Dependency factory: session cookie + role check for JSON API."""

    def _dep(request: Request, db: Session = Depends(get_db)) -> User:
        user = require_session_user(request, db)
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "forbidden",
                        "message": f"Role {user.role} not permitted; need one of {roles}",
                    }
                },
            )
        return user

    return _dep


# Backwards-compatible names used by API routers (now session-based, not X-User-Id)
def require_admin(request: Request, db: Session = Depends(get_db)) -> User:
    return require_session_role(["admin"])(request, db)


def require_reviewer_or_admin(request: Request, db: Session = Depends(get_db)) -> User:
    return require_session_role(["admin", "reviewer"])(request, db)


def assert_safe_secrets() -> None:
    """Refuse to start with known-insecure defaults unless DEMO_MODE is on."""
    settings = get_settings()
    if settings.demo_mode:
        return
    insecure = []
    defaults = {
        "secret_key": {
            "dev-secret-change-me-in-production-32chars",
            "change-me-to-a-long-random-string-in-production",
            "docker-compose-dev-secret-change-in-prod-32ch",
            "docker-compose-dev-secret-change-in-prod",
        },
        "ledger_checkpoint_key": {
            "dev-ledger-hmac-key-change-me",
            "change-me-ledger-hmac-key",
            "docker-compose-ledger-hmac-key",
            "docker-compose-ledger-key",
        },
    }
    if settings.secret_key in defaults["secret_key"] or len(settings.secret_key) < 24:
        insecure.append("SECRET_KEY")
    if (
        settings.ledger_checkpoint_key in defaults["ledger_checkpoint_key"]
        or len(settings.ledger_checkpoint_key) < 16
    ):
        insecure.append("LEDGER_CHECKPOINT_KEY")
    if insecure:
        raise RuntimeError(
            f"Refusing to start: insecure default(s) for {', '.join(insecure)}. "
            "Set strong secrets or enable DEMO_MODE=true for local demos only."
        )
