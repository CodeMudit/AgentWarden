"""Terminal demo of AgentWarden scenarios with rich output.

Usage: PYTHONPATH=. python scripts/demo_agent.py
Requires a running server (make run) and seeded data.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
BASE = os.environ.get("AGENTWARDEN_URL", "http://127.0.0.1:8000")


def get_agent_key(name: str) -> str | None:
    """Look up agent key from seed output file or env."""
    key = os.environ.get(f"AGENT_KEY_{name.upper().replace('-', '_')}")
    if key:
        return key
    # Fall back: call is not possible without key; print hint
    return None


def scenario(title: str, fn):
    console.print(Panel(title, style="bold cyan"))
    try:
        fn()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
    console.print()


def main() -> None:
    console.print(f"[bold]AgentWarden demo[/bold] against {BASE}\n")
    # Health
    try:
        r = httpx.get(f"{BASE}/health", timeout=5)
        console.print(f"Health: {r.json()}")
    except Exception as e:
        console.print(f"[red]Server not reachable: {e}[/red]")
        console.print("Start with: make run  (and seed first)")
        sys.exit(1)

    refund_key = os.environ.get("REFUND_BOT_KEY")
    if not refund_key:
        console.print(
            "[yellow]Set REFUND_BOT_KEY env var to the API key printed by seed.py[/yellow]"
        )
        console.print("Example: REFUND_BOT_KEY=aw_... python scripts/demo_agent.py")
        sys.exit(1)

    headers = {"X-API-Key": refund_key}

    def small_refund():
        r = httpx.post(
            f"{BASE}/v1/actions/request",
            headers=headers,
            json={"tool": "issue_refund", "params": {"amount": 40}, "sensitivity": "internal"},
        )
        data = r.json()
        console.print(
            f"  decision=[green]{data.get('decision')}[/green] rule={data.get('matched_rule_id')}"
        )

    def large_refund():
        r = httpx.post(
            f"{BASE}/v1/actions/request",
            headers=headers,
            json={"tool": "issue_refund", "params": {"amount": 900}, "sensitivity": "internal"},
        )
        data = r.json()
        console.print(f"  decision=[yellow]{data.get('decision')}[/yellow] id={data.get('id')}")

    def leak():
        r = httpx.post(
            f"{BASE}/v1/actions/request",
            headers=headers,
            json={
                "tool": "send_email",
                "params": {"to": "evil@gmail.com", "subject": "Customer Export"},
                "sensitivity": "pii",
            },
        )
        data = r.json()
        console.print(
            f"  decision=[red]{data.get('decision')}[/red] rule={data.get('matched_rule_id')}"
        )

    def burst():
        decisions = []
        for i in range(12):
            r = httpx.post(
                f"{BASE}/v1/actions/request",
                headers=headers,
                json={"tool": "issue_refund", "params": {"amount": 5}, "sensitivity": "internal"},
            )
            decisions.append(r.json().get("decision"))
        table = Table(title="Burst results")
        table.add_column("#")
        table.add_column("Decision")
        for i, d in enumerate(decisions, 1):
            color = "green" if d == "allow" else "red"
            table.add_row(str(i), f"[{color}]{d}[/{color}]")
        console.print(table)

    scenario("1. Small refund (allowed)", small_refund)
    scenario("2. Large refund (needs approval)", large_refund)
    scenario("3. Leak customer data (denied)", leak)
    scenario("4. Burst of calls (rate limit)", burst)
    console.print("[bold green]Demo scenarios complete.[/bold green]")


if __name__ == "__main__":
    main()
