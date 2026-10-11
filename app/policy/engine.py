"""Pure, deterministic policy evaluator. No DB, no I/O."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

ALLOWED_EFFECTS = {"allow", "deny", "require_approval"}
ALLOWED_CONDITION_TYPES = {
    "amount_gt",
    "amount_gte",
    "amount_lt",
    "amount_lte",
    "domain_in",
    "domain_not_in",
    "sensitivity_in",
    "time_window",
    "rate_limit",
    "param_matches",
}


@dataclass
class Decision:
    effect: str  # allow | deny | require_approval
    matched_rule_id: str | None
    reason: str
    policy_version: int | None = None


@dataclass
class RequestContext:
    agent_name: str
    tool: str
    params: dict[str, Any] = field(default_factory=dict)
    sensitivity: str = "internal"
    now: datetime | None = None


def _extract_domain(value: str) -> str | None:
    """Extract domain from an email address or URL."""
    if not value or not isinstance(value, str):
        return None
    value = value.strip()
    if "@" in value and "://" not in value:
        parts = value.rsplit("@", 1)
        if len(parts) == 2:
            return parts[1].lower()
        return None
    try:
        if "://" not in value:
            value = "http://" + value
        parsed = urlparse(value)
        host = parsed.hostname
        return host.lower() if host else None
    except Exception:
        return None


def _get_field(params: dict[str, Any], field_name: str) -> Any:
    if field_name in params:
        return params[field_name]
    parts = field_name.split(".")
    cur: Any = params
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur


def _eval_condition(
    cond: dict[str, Any],
    ctx: RequestContext,
    history_counts: dict[str, int],
    now: datetime,
) -> tuple[bool, str]:
    """Return (holds, explanation fragment)."""
    ctype = cond.get("type")
    if ctype not in ALLOWED_CONDITION_TYPES:
        return False, f"unknown condition type '{ctype}'"

    if ctype in ("amount_gt", "amount_gte", "amount_lt", "amount_lte"):
        field_name = cond.get("field", "amount")
        raw = _get_field(ctx.params, field_name)
        try:
            amount = float(raw)
        except (TypeError, ValueError):
            return False, f"{field_name} is not a number"
        threshold = float(cond["value"])
        ops = {
            "amount_gt": (amount > threshold, f"{field_name}={amount} > {threshold}"),
            "amount_gte": (amount >= threshold, f"{field_name}={amount} >= {threshold}"),
            "amount_lt": (amount < threshold, f"{field_name}={amount} < {threshold}"),
            "amount_lte": (amount <= threshold, f"{field_name}={amount} <= {threshold}"),
        }
        holds, expl = ops[ctype]
        return holds, expl

    if ctype in ("domain_in", "domain_not_in"):
        field_name = cond.get("field", "to")
        raw = _get_field(ctx.params, field_name)
        domain = _extract_domain(str(raw) if raw is not None else "")
        allowed = [d.lower() for d in cond.get("value", [])]
        if domain is None:
            return False, f"could not extract domain from {field_name}={raw!r}"
        in_list = domain in allowed
        if ctype == "domain_in":
            return in_list, f"domain {domain} is in {allowed}"
        return (not in_list), f"domain {domain} is not in {allowed}"

    if ctype == "sensitivity_in":
        values = [v.lower() for v in cond.get("value", [])]
        holds = ctx.sensitivity.lower() in values
        return holds, f"sensitivity={ctx.sensitivity} in {values}"

    if ctype == "time_window":
        conf = cond.get("value") or {}
        hours = conf.get("hours")
        weekdays = conf.get("weekdays")
        current = now.astimezone(UTC) if now.tzinfo else now.replace(tzinfo=UTC)
        wd = current.weekday()
        hr = current.hour
        parts = []
        holds = True
        if weekdays is not None:
            ok = wd in weekdays
            holds = holds and ok
            parts.append(f"weekday={wd} in {weekdays}={ok}")
        if hours is not None:
            if len(hours) == 2 and not isinstance(hours[0], list):
                start, end = hours
                ok = start <= hr < end
            else:
                ok = hr in hours
            holds = holds and ok
            parts.append(f"hour={hr} allowed={ok}")
        return holds, "; ".join(parts) if parts else "time_window ok"

    if ctype == "rate_limit":
        conf = cond.get("value") or {}
        max_n = int(conf.get("max", 0))
        window = int(conf.get("window_seconds", 60))
        key = f"{ctx.agent_name}:{ctx.tool}:{window}"
        count = history_counts.get(key, 0)
        # TRUE when count >= max so a deny rule fires when over the limit
        holds = count >= max_n
        return holds, f"rate count={count} >= max={max_n} (window={window}s)"

    if ctype == "param_matches":
        field_name = cond.get("field", "")
        pattern = cond.get("value", "")
        raw = _get_field(ctx.params, field_name)
        text = "" if raw is None else str(raw)
        try:
            m = re.search(pattern, text)
        except re.error as e:
            return False, f"bad regex: {e}"
        holds = m is not None
        return holds, f"{field_name} matches /{pattern}/ = {holds}"

    return False, f"unhandled condition {ctype}"


def _rule_matches(
    rule: dict[str, Any],
    ctx: RequestContext,
    history_counts: dict[str, int],
    now: datetime,
) -> tuple[bool, str]:
    match = rule.get("match") or {}
    agents = match.get("agents")
    tools = match.get("tools")
    if agents is not None and ctx.agent_name not in agents:
        return False, "agent not in match.agents"
    if tools is not None and ctx.tool not in tools:
        return False, "tool not in match.tools"

    conditions = rule.get("conditions") or []
    explanations: list[str] = []
    for cond in conditions:
        holds, expl = _eval_condition(cond, ctx, history_counts, now)
        explanations.append(expl)
        if not holds:
            return False, "; ".join(explanations)
    return True, "; ".join(explanations) if explanations else "match ok"


def evaluate(
    policy: dict[str, Any],
    request_context: RequestContext,
    history_counts: dict[str, int] | None = None,
    now: datetime | None = None,
) -> Decision:
    """Evaluate policy against request. Default deny if no rule matches."""
    history_counts = history_counts or {}
    now = now or request_context.now or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    default_effect = (policy.get("default_effect") or "deny").lower()
    if default_effect not in ALLOWED_EFFECTS:
        default_effect = "deny"

    rules = list(policy.get("rules") or [])
    rules_sorted = sorted(rules, key=lambda r: int(r.get("priority", 100)))

    for rule in rules_sorted:
        matched, expl = _rule_matches(rule, request_context, history_counts, now)
        if matched:
            effect = (rule.get("effect") or "deny").lower()
            if effect not in ALLOWED_EFFECTS:
                effect = "deny"
            rid = rule.get("id", "unknown")
            desc = rule.get("description") or rid
            reason = f"Matched rule '{rid}' (priority {rule.get('priority', '?')}): {expl}"
            if desc and desc != rid:
                reason = (
                    f"Matched rule '{rid}' (priority {rule.get('priority', '?')}): {desc}. {expl}"
                )
            return Decision(effect=effect, matched_rule_id=rid, reason=reason)

    return Decision(
        effect=default_effect,
        matched_rule_id=None,
        reason=f"No matching rule; default_effect={default_effect}",
    )


def validate_policy(policy: dict[str, Any]) -> list[str]:
    """Return list of validation errors (empty = valid)."""
    errors: list[str] = []
    if not isinstance(policy, dict):
        return ["policy must be an object"]

    default = policy.get("default_effect", "deny")
    if default not in ALLOWED_EFFECTS:
        errors.append(f"default_effect must be one of {sorted(ALLOWED_EFFECTS)}")

    rules = policy.get("rules")
    if rules is None:
        errors.append("rules is required")
        return errors
    if not isinstance(rules, list):
        errors.append("rules must be a list")
        return errors

    seen_ids: set[str] = set()
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append(f"rules[{i}] must be an object")
            continue
        rid = rule.get("id")
        if not rid:
            errors.append(f"rules[{i}] missing id")
        elif rid in seen_ids:
            errors.append(f"duplicate rule id '{rid}'")
        else:
            seen_ids.add(rid)

        if "priority" not in rule:
            errors.append(f"rules[{i}] ('{rid}') missing priority")
        else:
            try:
                int(rule["priority"])
            except (TypeError, ValueError):
                errors.append(f"rules[{i}] priority must be an int")

        effect = rule.get("effect")
        if effect not in ALLOWED_EFFECTS:
            errors.append(f"rules[{i}] effect must be one of {sorted(ALLOWED_EFFECTS)}")

        for j, cond in enumerate(rule.get("conditions") or []):
            if not isinstance(cond, dict):
                errors.append(f"rules[{i}].conditions[{j}] must be an object")
                continue
            ctype = cond.get("type")
            if ctype not in ALLOWED_CONDITION_TYPES:
                errors.append(
                    f"rules[{i}].conditions[{j}] unknown type '{ctype}'; "
                    f"allowed={sorted(ALLOWED_CONDITION_TYPES)}"
                )
            if ctype == "param_matches":
                try:
                    re.compile(cond.get("value") or "")
                except re.error as e:
                    errors.append(f"rules[{i}].conditions[{j}] bad regex: {e}")
            if ctype in ("domain_in", "domain_not_in", "sensitivity_in"):
                if not isinstance(cond.get("value"), list):
                    errors.append(f"rules[{i}].conditions[{j}] value must be a list")
            if ctype in ("amount_gt", "amount_gte", "amount_lt", "amount_lte"):
                try:
                    float(cond.get("value"))
                except (TypeError, ValueError):
                    errors.append(f"rules[{i}].conditions[{j}] value must be a number")

    return errors
