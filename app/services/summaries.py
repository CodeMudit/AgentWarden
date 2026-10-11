"""Template-based plain-language summaries. Optional LLM rewording if key set."""

from __future__ import annotations

from typing import Any


def build_summary(
    tool: str,
    params: dict[str, Any],
    sensitivity: str,
    agent_name: str,
) -> str:
    """Deterministic template summary – no LLM required."""
    if tool == "issue_refund":
        amount = params.get("amount", "?")
        order = params.get("order_id") or params.get("order", "")
        extra = f" for order {order}" if order else ""
        return (
            f"Agent '{agent_name}' wants to issue a refund of {amount}{extra}. "
            f"Data sensitivity: {sensitivity}."
        )
    if tool == "send_email":
        to = params.get("to", "?")
        subject = params.get("subject", "(no subject)")
        return (
            f"Agent '{agent_name}' wants to send an email to {to} "
            f"with subject '{subject}'. Data sensitivity: {sensitivity}."
        )
    # generic
    keys = ", ".join(f"{k}={v!r}" for k, v in list(params.items())[:5])
    return (
        f"Agent '{agent_name}' requests tool '{tool}' "
        f"with params [{keys}]. Sensitivity: {sensitivity}."
    )


def maybe_reword_summary(summary: str) -> str:
    """If ANTHROPIC_API_KEY is set, optionally reword. Otherwise return as-is.

    Phase 1: always return template summary. LLM path is a no-op unless key present
    and a future enhancement enables it. Never changes the decision.
    """
    from app.config import get_settings

    settings = get_settings()
    if not settings.anthropic_api_key:
        return summary
    # Optional: call Anthropic to reword. Kept as pass-through for reliability
    # in Phase 1; decision path never depends on this.
    return summary
