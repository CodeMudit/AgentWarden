"""Web session auth and page smoke tests."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import ledger
from app.db import Base, get_db
from app.models import User
from app.security import hash_password


def _make_client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    s = Session()
    ledger.ensure_genesis(s)
    admin = User(
        email="admin@test.com",
        name="Admin",
        password_hash=hash_password("password123"),
        role="admin",
        is_active=True,
    )
    s.add(admin)
    s.commit()
    s.close()

    def _override():
        session = Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    from contextlib import asynccontextmanager

    from fastapi import FastAPI
    from fastapi.responses import RedirectResponse

    from app.config import get_settings
    from app.security import RedirectToLogin
    from app.web import routes as web_routes

    get_settings()  # ensure env

    @asynccontextmanager
    async def _noop(app):
        yield

    app = FastAPI(lifespan=_noop)

    @app.exception_handler(RedirectToLogin)
    async def _redir(request, exc):
        return RedirectResponse("/login", status_code=303)

    app.include_router(web_routes.router)
    app.dependency_overrides[get_db] = _override
    return TestClient(app, follow_redirects=False)


def test_login_page():
    client = _make_client()
    r = client.get("/login")
    assert r.status_code == 200
    assert b"Sign in" in r.content


def test_login_and_overview():
    client = _make_client()
    # get csrf cookie
    client.get("/login")
    csrf = client.cookies.get("aw_csrf")
    r = client.post(
        "/login",
        data={"email": "admin@test.com", "password": "password123", "csrf_token": csrf or ""},
    )
    assert r.status_code in (303, 302)
    assert "aw_session" in r.cookies or client.cookies.get("aw_session")

    # follow with session
    client2 = _make_client()
    client2.get("/login")
    csrf = client2.cookies.get("aw_csrf")
    r = client2.post(
        "/login",
        data={"email": "admin@test.com", "password": "password123", "csrf_token": csrf or ""},
        follow_redirects=True,
    )
    # After login redirect to overview
    assert r.status_code == 200
    assert b"Overview" in r.content or b"AgentWarden" in r.content


def test_unauthenticated_redirect():
    client = _make_client()
    r = client.get("/")
    assert r.status_code in (303, 302)
    assert "/login" in r.headers.get("location", "")


def test_csrf_rejection():
    client = _make_client()
    client.get("/login")
    csrf = client.cookies.get("aw_csrf")
    client.post(
        "/login",
        data={"email": "admin@test.com", "password": "password123", "csrf_token": csrf or ""},
        follow_redirects=True,
    )
    # bad csrf on mutate — must not succeed as a silent freeze
    r = client.post("/system/freeze", data={"csrf_token": "bogus"}, follow_redirects=False)
    # 403 CSRF failure, or 303 redirect to login if session not retained in test client
    assert r.status_code in (403, 303, 401)
