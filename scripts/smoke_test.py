"""End-to-end smoke test against a running server with seeded DB.

Exit non-zero on any failure. Used by `make verify`.
Authenticates humans via session cookies (POST /login), never X-User-Id.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
from rich.console import Console
from sqlalchemy import select

from app.db import SessionLocal, init_db
from app.models import Agent, User
from app.security import generate_api_key

console = Console()
BASE = os.environ.get("AGENTWARDEN_URL", "http://127.0.0.1:8000")
failed = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global failed
    if cond:
        console.print(f"  [green]PASS[/green] {name}")
    else:
        console.print(f"  [red]FAIL[/red] {name} {detail}")
        failed += 1


def login(client: httpx.Client, email: str, password: str) -> None:
    # Establish CSRF cookie
    client.get(f"{BASE}/login")
    csrf = client.cookies.get("aw_csrf") or ""
    r = client.post(
        f"{BASE}/login",
        data={"email": email, "password": password, "csrf_token": csrf},
        follow_redirects=False,
    )
    if r.status_code not in (303, 302, 200):
        raise RuntimeError(f"login failed for {email}: {r.status_code} {r.text[:200]}")


def main() -> int:
    console.print(f"[bold]Smoke test[/bold] → {BASE}")

    try:
        r = httpx.get(f"{BASE}/health", timeout=5)
        check("health", r.status_code == 200 and r.json().get("status") == "ok")
    except Exception as e:
        console.print(f"[red]Server unreachable: {e}[/red]")
        return 1

    # Prove forged X-User-Id is rejected
    r = httpx.get(f"{BASE}/v1/agents", headers={"X-User-Id": "1"}, timeout=5)
    check("forged X-User-Id rejected", r.status_code in (401, 403), r.text[:120])

    init_db()
    db = SessionLocal()
    try:
        admin = db.execute(select(User).where(User.role == "admin")).scalars().first()
        reviewer_a = db.execute(
            select(User).where(User.email == "reviewer_a@demo.local")
        ).scalar_one_or_none()
        reviewer_b = db.execute(
            select(User).where(User.email == "reviewer_b@demo.local")
        ).scalar_one_or_none()
        agent = db.execute(select(Agent).where(Agent.name == "refund-bot")).scalar_one_or_none()
        check("seed users", admin is not None and reviewer_a is not None and reviewer_b is not None)
        check("seed agent", agent is not None)
        if not agent:
            return 1

        full, prefix, key_hash = generate_api_key()
        agent.api_key_prefix = prefix
        agent.api_key_hash = key_hash
        db.commit()
        key = full
        agent_headers = {"X-API-Key": key}

        with httpx.Client(timeout=15, follow_redirects=False) as human:
            login(human, "admin@demo.local", "demo-admin-pass")

            # Session works for list agents
            r = human.get(f"{BASE}/v1/agents")
            check("session auth lists agents", r.status_code == 200, r.text[:120])

            # 1. Allowed small refund
            r = httpx.post(
                f"{BASE}/v1/actions/request",
                headers=agent_headers,
                json={"tool": "issue_refund", "params": {"amount": 40}, "sensitivity": "internal"},
            )
            data = r.json()
            check("small refund allow", data.get("decision") == "allow", str(data))

            # 2. Large refund → approve as reviewer_b
            r = httpx.post(
                f"{BASE}/v1/actions/request",
                headers=agent_headers,
                json={"tool": "issue_refund", "params": {"amount": 900}, "sensitivity": "internal"},
            )
            data = r.json()
            check("large refund pending", data.get("decision") == "require_approval", str(data))
            action_id = data.get("id")

            with httpx.Client(timeout=15, follow_redirects=False) as rev:
                login(rev, "reviewer_b@demo.local", "demo-reviewer-pass")
                r = rev.post(
                    f"{BASE}/v1/approvals/{action_id}/approve",
                    json={"reason": "Smoke test approval – verified customer request"},
                )
                check(
                    "approve large refund",
                    r.status_code == 200 and r.json().get("status") == "approved",
                    r.text[:200],
                )

            # 3. Denied PII leak
            r = httpx.post(
                f"{BASE}/v1/actions/request",
                headers=agent_headers,
                json={
                    "tool": "send_email",
                    "params": {"to": "x@gmail.com", "subject": "Export"},
                    "sensitivity": "pii",
                },
            )
            check("pii leak deny", r.json().get("decision") == "deny", r.text[:120])

            # 4. Ledger verify PASS
            r = human.post(f"{BASE}/v1/ledger/verify")
            check(
                "ledger verify PASS",
                r.status_code == 200 and r.json().get("ok") is True,
                r.text[:120],
            )

            # 5. Tamper then FAIL
            from scripts.tamper import repair, tamper

            tamper()
            r = human.post(f"{BASE}/v1/ledger/verify")
            body = r.json()
            check("ledger verify FAIL after tamper", body.get("ok") is False, str(body))

            # 6. Repair then PASS
            repair()
            r = human.post(f"{BASE}/v1/ledger/verify")
            check("ledger verify PASS after repair", r.json().get("ok") is True, r.text[:120])

    finally:
        db.close()

    if failed:
        console.print(f"\n[red]{failed} check(s) failed[/red]")
        return 1
    console.print("\n[bold green]All smoke checks passed[/bold green]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
