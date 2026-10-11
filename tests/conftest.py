"""Shared pytest fixtures."""

from __future__ import annotations

import os

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "test-secret-key-for-pytest"
os.environ["LEDGER_CHECKPOINT_KEY"] = "test-ledger-hmac-key"
os.environ["DEMO_MODE"] = "true"
os.environ["APPROVAL_SLA_SECONDS"] = "900"

# Clear settings before imports that use them
from app.config import get_settings

get_settings.cache_clear()

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import ledger
from app.db import Base, get_db
from app.models import User
from app.security import generate_api_key, hash_password


@pytest.fixture()
def db_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _fk(dbapi_conn, _):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture()
def db(db_engine):
    Session = sessionmaker(bind=db_engine, autocommit=False, autoflush=False)
    session = Session()
    ledger.ensure_genesis(session)
    session.commit()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db_engine, db):
    """TestClient wired to the same in-memory engine as `db` fixture."""
    Session = sessionmaker(bind=db_engine, autocommit=False, autoflush=False)

    def _override_get_db():
        session = Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # Import create_app late; disable lifespan side-effects by building app
    # without starting escalation against global engine.
    from contextlib import asynccontextmanager

    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    from app import __version__
    from app.api import actions, agents, approvals, ledger_api, policies, system, users
    from app.config import get_settings

    settings = get_settings()

    @asynccontextmanager
    async def _noop_lifespan(app: FastAPI):
        yield

    app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=_noop_lifespan)

    @app.get("/health")
    def health():
        return JSONResponse(
            {
                "status": "ok",
                "app": settings.app_name,
                "version": settings.app_version or __version__,
                "db": "ok",
                "ledger_head_seq": 1,
            }
        )

    app.include_router(actions.router, prefix="/v1")
    app.include_router(approvals.router, prefix="/v1")
    app.include_router(agents.router, prefix="/v1")
    app.include_router(policies.router, prefix="/v1")
    app.include_router(ledger_api.router, prefix="/v1")
    app.include_router(system.router, prefix="/v1")
    app.include_router(users.router, prefix="/v1")
    app.dependency_overrides[get_db] = _override_get_db

    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def admin_user(db):
    u = User(
        email="admin@test.com",
        name="Admin",
        password_hash=hash_password("password123"),
        role="admin",
        is_active=True,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture()
def reviewer_a(db):
    u = User(
        email="reviewer_a@test.com",
        name="Reviewer A",
        password_hash=hash_password("password123"),
        role="reviewer",
        is_active=True,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture()
def reviewer_b(db):
    u = User(
        email="reviewer_b@test.com",
        name="Reviewer B",
        password_hash=hash_password("password123"),
        role="reviewer",
        is_active=True,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture()
def agent_with_key(db, reviewer_a):
    from app.models import Agent

    full, prefix, key_hash = generate_api_key()
    agent = Agent(
        name="refund-bot",
        purpose="Issues refunds",
        owner_user_id=reviewer_a.id,
        risk_tier="medium",
        status="active",
        api_key_prefix=prefix,
        api_key_hash=key_hash,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return agent, full


@pytest.fixture()
def active_policy(db, admin_user):
    from app.models import Policy

    rules = {
        "default_effect": "deny",
        "rules": [
            {
                "id": "refund-small-auto",
                "priority": 10,
                "description": "Refunds up to 100 are auto-approved",
                "match": {"agents": ["refund-bot"], "tools": ["issue_refund"]},
                "conditions": [{"type": "amount_lte", "field": "amount", "value": 100}],
                "effect": "allow",
            },
            {
                "id": "refund-large-review",
                "priority": 20,
                "match": {"agents": ["refund-bot"], "tools": ["issue_refund"]},
                "conditions": [{"type": "amount_gt", "field": "amount", "value": 100}],
                "effect": "require_approval",
            },
            {
                "id": "block-external-pii",
                "priority": 5,
                "match": {"tools": ["send_email"]},
                "conditions": [
                    {"type": "domain_not_in", "field": "to", "value": ["company.com"]},
                    {"type": "sensitivity_in", "value": ["confidential", "pii"]},
                ],
                "effect": "deny",
            },
            {
                "id": "rate-limit-refund",
                "priority": 3,
                "match": {"agents": ["refund-bot"], "tools": ["issue_refund"]},
                "conditions": [{"type": "rate_limit", "value": {"max": 5, "window_seconds": 60}}],
                "effect": "deny",
            },
        ],
    }
    p = Policy(version=1, rules=rules, is_active=True, created_by=admin_user.id, note="test")
    db.add(p)
    db.commit()
    db.refresh(p)
    return p
