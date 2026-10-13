"""Judge landing page + one-tap reviewer sign-in (DEMO_MODE only)."""

from __future__ import annotations

from app.config import get_settings
from app.models import User
from app.security import SESSION_COOKIE, hash_password


def _csrf(client) -> str:
    r = client.get("/judge")
    assert r.status_code == 200
    return client.cookies.get("aw_csrf")


def test_judge_page_is_public_and_has_form(client):
    r = client.get("/judge")
    assert r.status_code == 200
    assert "/judge/enter" in r.text


def test_judge_enter_logs_in_as_reviewer(client, db):
    db.add(
        User(
            email="reviewer_b@demo.local",
            name="Reviewer B",
            password_hash=hash_password("demo-reviewer-pass"),
            role="reviewer",
            is_active=True,
        )
    )
    db.commit()
    token = _csrf(client)
    r = client.post("/judge/enter", data={"csrf_token": token}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/approvals"
    assert SESSION_COOKIE in r.headers.get("set-cookie", "")


def test_judge_enter_requires_csrf(client):
    client.get("/judge")
    r = client.post("/judge/enter", data={"csrf_token": "wrong"}, follow_redirects=False)
    assert r.status_code == 403


def test_judge_disabled_outside_demo_mode(client):
    settings = get_settings()
    settings.demo_mode = False
    try:
        assert client.get("/judge").status_code == 404
        assert client.post("/judge/enter", data={"csrf_token": "x"}).status_code == 404
    finally:
        settings.demo_mode = True
