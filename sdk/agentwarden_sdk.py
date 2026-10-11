"""AgentWarden Python SDK – client + @governed decorator."""

from __future__ import annotations

import functools
import time
from typing import Any, Callable

import httpx


class ActionDenied(Exception):
    def __init__(self, action_id: int | None, reason: str):
        self.action_id = action_id
        self.reason = reason
        super().__init__(reason)


class ApprovalTimeout(Exception):
    def __init__(self, action_id: int, timeout: float):
        self.action_id = action_id
        self.timeout = timeout
        super().__init__(f"Approval timed out after {timeout}s for action {action_id}")


class AgentWarden:
    def __init__(self, base_url: str, api_key: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"X-API-Key": api_key},
            timeout=timeout,
        )

    def request(
        self,
        tool: str,
        params: dict[str, Any] | None = None,
        sensitivity: str = "internal",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        r = self._client.post(
            "/v1/actions/request",
            json={
                "tool": tool,
                "params": params or {},
                "sensitivity": sensitivity,
                "context": context,
            },
        )
        r.raise_for_status()
        return r.json()

    def get_status(self, action_id: int) -> dict[str, Any]:
        r = self._client.get(f"/v1/actions/{action_id}")
        r.raise_for_status()
        return r.json()

    def complete(
        self, action_id: int, success: bool = True, result: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        r = self._client.post(
            f"/v1/actions/{action_id}/complete",
            json={"success": success, "result": result},
        )
        r.raise_for_status()
        return r.json()

    def wait_for_decision(
        self,
        action_id: int,
        poll_interval: float = 1.0,
        timeout: float = 120.0,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.get_status(action_id)
            st = status.get("status")
            if st in ("allowed", "approved"):
                return status
            if st in ("denied", "rejected"):
                raise ActionDenied(action_id, status.get("decision_reason") or status.get("reason") or "denied")
            if st == "escalated":
                # still waiting for admin decision
                pass
            time.sleep(poll_interval)
        raise ApprovalTimeout(action_id, timeout)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> AgentWarden:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


def governed(
    tool: str,
    sensitivity: str = "internal",
    base_url: str = "http://localhost:8000",
    api_key: str | None = None,
    approval_timeout: float = 120.0,
):
    """Decorator: request permission, wait if needed, run function, report completion.

    Usage:
        client = AgentWarden("http://localhost:8000", api_key="aw_...")

        @governed(tool="issue_refund", sensitivity="internal")
        def issue_refund(amount, order_id, _warden=None, _action_id=None):
            return {"refund_id": "R-1"}

        # Prefer binding client:
        issue_refund = governed(tool="issue_refund")(fn)
        # and call with warden via attribute, or use AgentWarden methods directly.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            key = api_key or kwargs.pop("api_key", None)
            url = kwargs.pop("base_url", base_url)
            warden: AgentWarden | None = kwargs.pop("_warden", None)
            own_client = False
            if warden is None:
                if not key:
                    raise ValueError("api_key or _warden required")
                warden = AgentWarden(url, key)
                own_client = True
            params = {k: v for k, v in kwargs.items() if not k.startswith("_")}
            # also map positional via fn annotations lightly – pass kwargs-style only for simplicity
            try:
                decision = warden.request(tool=tool, params=params or dict(kwargs), sensitivity=sensitivity)
                action_id = decision["id"]
                if decision.get("decision") == "deny":
                    raise ActionDenied(action_id, decision.get("reason") or "denied")
                if decision.get("decision") == "require_approval":
                    status = warden.wait_for_decision(action_id, timeout=approval_timeout)
                    if status.get("status") in ("denied", "rejected"):
                        raise ActionDenied(action_id, status.get("decision_reason") or "rejected")
                result = fn(*args, **kwargs)
                warden.complete(action_id, success=True, result=result if isinstance(result, dict) else {"value": result})
                return result
            except ActionDenied:
                raise
            except ApprovalTimeout:
                raise
            except Exception as e:
                if "action_id" in locals():
                    try:
                        warden.complete(action_id, success=False, result={"error": str(e)})
                    except Exception:
                        pass
                raise
            finally:
                if own_client and warden:
                    warden.close()

        return wrapper

    return decorator
