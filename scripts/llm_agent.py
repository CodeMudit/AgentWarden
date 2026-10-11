"""Optional real-LLM tool-calling agent (bonus).

Exits cleanly if ANTHROPIC_API_KEY is not set. Every tool call goes through
the SDK @governed decorator before executing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> int:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        print("ANTHROPIC_API_KEY not set — llm_agent is optional and will exit.")
        print("Core demo does not require this script.")
        return 0

    agent_key = os.environ.get("REFUND_BOT_KEY")
    if not agent_key:
        print("Set REFUND_BOT_KEY to a seeded agent API key.")
        return 1

    base = os.environ.get("AGENTWARDEN_URL", "http://127.0.0.1:8000")
    model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

    try:
        import anthropic
    except ImportError:
        print("pip install anthropic to use llm_agent")
        return 1

    from sdk.agentwarden_sdk import ActionDenied, AgentWarden, ApprovalTimeout

    client = anthropic.Anthropic(api_key=key)
    warden = AgentWarden(base, agent_key)

    tools = [
        {
            "name": "issue_refund",
            "description": "Issue a customer refund",
            "input_schema": {
                "type": "object",
                "properties": {
                    "amount": {"type": "number"},
                    "order_id": {"type": "string"},
                },
                "required": ["amount"],
            },
        },
        {
            "name": "send_email",
            "description": "Send an email",
            "input_schema": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                },
                "required": ["to", "subject"],
            },
        },
    ]

    prompt = os.environ.get(
        "LLM_PROMPT",
        "Issue a refund of 40 for order ORD-1, then try to email a customer export to someone@gmail.com marked sensitive.",
    )
    print(f"Model={model} prompt={prompt!r}")
    msg = client.messages.create(
        model=model,
        max_tokens=1024,
        tools=tools,
        messages=[{"role": "user", "content": prompt}],
    )
    for block in msg.content:
        if block.type != "tool_use":
            continue
        print(f"Model requested tool={block.name} input={block.input}")
        sens = "pii" if block.name == "send_email" else "internal"
        try:
            decision = warden.request(block.name, dict(block.input), sensitivity=sens)
            print(f"  AgentWarden decision={decision.get('decision')} reason={decision.get('reason')}")
            if decision.get("decision") == "deny":
                print("  Tool NOT executed")
                continue
            if decision.get("decision") == "require_approval":
                print("  Waiting for approval…")
                status = warden.wait_for_decision(decision["id"], timeout=60)
                if status.get("status") in ("denied", "rejected"):
                    print("  Rejected — tool NOT executed")
                    continue
            # execute (stub)
            result = {"ok": True, "tool": block.name, "echo": block.input}
            warden.complete(decision["id"], success=True, result=result)
            print(f"  Tool executed: {result}")
        except (ActionDenied, ApprovalTimeout) as e:
            print(f"  Blocked: {e}")
    warden.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
