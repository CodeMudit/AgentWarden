"""End-to-end smoke test against a running server with seeded DB.

Exit non-zero on any failure. Used by `make verify`.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
from rich.console import Console
from sqlalchemy import select

from app.db import SessionLocal, init_db
from app.models import Agent, User
from app.security import generate_api_key, hash_api_key
from app import ledger

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


def main() -> int:
    console.print(f"[bold]Smoke test[/bold] → {BASE}")

    # Health
    try:
        r = httpx.get(f"{BASE}/health", timeout=5)
        check("health", r.status_code == 200 and r.json().get("status") == "ok")
    except Exception as e:
        console.print(f"[red]Server unreachable: {e}[/red]")
        return 1

    init_db()
    db = SessionLocal()
    try:
        admin = db.execute(select(User).where(User.role == "admin")).scalars().first()
        reviewer_a = db.execute(select(User).where(User.email == "reviewer_a@demo.local")).scalar_one_or_none()
        reviewer_b = db.execute(select(User).where(User.email == "reviewer_b@demo.local")).scalar_one_or_none()
        agent = db.execute(select(Agent).where(Agent.name == "refund-bot")).scalar_one_or_none()
        check("seed users", admin is not None and reviewer_a is not None and reviewer_b is not None)
        check("seed agent", agent is not None)
        if not agent:
            return 1

        # Rotate a known API key for the smoke test so we can authenticate
        full, prefix, key_hash = generate_api_key()
        agent.api_key_prefix = prefix
        agent.api_key_hash = key_hash
        db.commit()
        key = full
        headers = {"X-API-Key": key}
        admin_h = {"X-User-Id": str(admin.id)}
        rev_b_h = {"X-User-Id": str(reviewer_b.id)}

        # 1. Allowed small refund
        r = httpx.post(
            f"{BASE}/v1/actions/request",
            headers=headers,
            json={"tool": "issue_refund", "params": {"amount": 40}, "sensitivity": "internal"},
            timeout=10,
        )
        data = r.json()
        check("small refund allow", data.get("decision") == "allow", str(data))

        # 2. Large refund → approve
        r = httpx.post(
            f"{BASE}/v1/actions/request",
            headers=headers,
            json={"tool": "issue_refund", "params": {"amount": 900}, "sensitivity": "internal"},
            timeout=10,
        )
        data = r.json()
        check("large refund pending", data.get("decision") == "require_approval", str(data))
        action_id = data.get("id")
        r = httpx.post(
            f"{BASE}/v1/approvals/{action_id}/approve",
            headers=rev_b_h,
            json={"reason": "Smoke test approval – verified customer request"},
            timeout=10,
        )
        check("approve large refund", r.status_code == 200 and r.json().get("status") == "approved", r.text)

        # 3. Denied PII leak
        r = httpx.post(
            f"{BASE}/v1/actions/request",
            headers=headers,
            json={
                "tool": "send_email",
                "params": {"to": "x@gmail.com", "subject": "Export"},
                "sensitivity": "pii",
            },
            timeout=10,
        )
        check("pii leak deny", r.json().get("decision") == "deny", r.text)

        # 4. Ledger verify PASS
        r = httpx.post(f"{BASE}/v1/ledger/verify", headers=admin_h, timeout=10)
        check("ledger verify PASS", r.status_code == 200 and r.json().get("ok") is True, r.text)

        # 5. Tamper then FAIL
        from scripts.tamper import tamper, repair

        tamper()
        r = httpx.post(f"{BASE}/v1/ledger/verify", headers=admin_h, timeout=10)
        body = r.json()
        check("ledger verify FAIL after tamper", body.get("ok") is False, str(body))

        # 6. Repair then PASS
        repair()
        r = httpx.post(f"{BASE}/v1/ledger/verify", headers=admin_h, timeout=10)
        check("ledger verify PASS after repair", r.json().get("ok") is True, r.text)

    finally:
        db.close()

    if failed:
        console.print(f"\n[red]{failed} check(s) failed[/red]")
        return 1
    console.print("\n[bold green]All smoke checks passed[/bold green]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
