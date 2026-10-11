"""HTML routes: auth, pages, HTMX partials."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import ledger
from app.config import get_settings
from app.db import get_db
from app.models import ActionRequest, Agent, LedgerEntry, Policy, User
from app.policy.engine import validate_policy
from app.policy.simulator import simulate
from app.security import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    check_login_rate_limit,
    create_session_token,
    generate_api_key,
    generate_csrf_token,
    get_current_user,
    record_login_attempt,
    require_web_user,
    verify_csrf,
    verify_password,
)
from app.services import approvals as approvals_svc
from app.services.approvals import ApprovalError
from app.services.killswitch import (
    freeze_system,
    get_system_state,
    resume_agent,
    suspend_agent,
    unfreeze_system,
)

router = APIRouter(tags=["web"])

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _ctx(request: Request, db: Session, **extra: Any) -> dict[str, Any]:
    settings = get_settings()
    user = get_current_user(request, db)
    csrf = request.cookies.get(CSRF_COOKIE) or ""
    frozen = False
    head = {"last_seq": 0, "last_hash": "0" * 64}
    try:
        state = get_system_state(db)
        frozen = state.is_frozen
        head = ledger.get_head(db)
    except Exception:
        pass
    return {
        "request": request,
        "current_user": user,
        "csrf_token": csrf,
        "app_version": settings.app_version,
        "demo_mode": settings.demo_mode,
        "system_frozen": frozen,
        "ledger_seq": head.get("last_seq"),
        "ledger_hash": head.get("last_hash"),
        **extra,
    }


def _ensure_csrf(response: Response, request: Request) -> str:
    token = request.cookies.get(CSRF_COOKIE)
    if not token:
        token = generate_csrf_token()
        response.set_cookie(
            CSRF_COOKIE,
            token,
            httponly=False,
            samesite="lax",
            max_age=60 * 60 * 12,
        )
    return token


# ---------- Auth ----------


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if get_current_user(request, db):
        return RedirectResponse("/", status_code=303)
    response = templates.TemplateResponse(request, "login.html", _ctx(request, db, error=None))
    _ensure_csrf(response, request)
    # refresh csrf in context
    response.headers.get("set-cookie", "")
    csrf = request.cookies.get(CSRF_COOKIE) or generate_csrf_token()
    response = templates.TemplateResponse(
        request, "login.html", {**_ctx(request, db, error=None), "csrf_token": csrf}
    )
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, samesite="lax", max_age=60 * 60 * 12)
    return response


@router.post("/login")
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    try:
        verify_csrf(request, csrf_token)
    except Exception:
        return templates.TemplateResponse(
            request,
            "login.html",
            _ctx(request, db, error="CSRF validation failed. Refresh and try again."),
            status_code=403,
        )
    client_ip = request.client.host if request.client else "unknown"
    try:
        check_login_rate_limit(client_ip)
    except HTTPException as e:
        msg = (
            e.detail["error"]["message"]
            if isinstance(e.detail, dict) and "error" in e.detail
            else "Too many login attempts"
        )
        return templates.TemplateResponse(
            request, "login.html", _ctx(request, db, error=msg), status_code=429
        )
    record_login_attempt(client_ip)
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is None or not user.is_active or not verify_password(password, user.password_hash):
        csrf = request.cookies.get(CSRF_COOKIE) or generate_csrf_token()
        resp = templates.TemplateResponse(
            request,
            "login.html",
            {**_ctx(request, db, error="Invalid email or password."), "csrf_token": csrf},
            status_code=401,
        )
        resp.set_cookie(CSRF_COOKIE, csrf, httponly=False, samesite="lax")
        return resp
    token = create_session_token(user.id)
    response = RedirectResponse("/", status_code=303)
    settings = get_settings()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=not settings.debug,
        max_age=60 * 60 * 12,
    )
    csrf = generate_csrf_token()
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, samesite="lax", max_age=60 * 60 * 12)
    try:
        ledger.append(
            db,
            event_type="user_login",
            actor_type="user",
            actor_id=str(user.id),
            subject_type="user",
            subject_id=str(user.id),
            payload={"email": user.email},
        )
        db.commit()
    except Exception:
        db.rollback()
    return response


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form(""), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


# ---------- Overview ----------


@router.get("/", response_class=HTMLResponse)
def overview(
    request: Request, db: Session = Depends(get_db), user: User = Depends(require_web_user)
):
    today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    actions_today = (
        db.execute(
            select(func.count()).select_from(ActionRequest).where(ActionRequest.created_at >= today)
        ).scalar()
        or 0
    )
    allowed = (
        db.execute(
            select(func.count())
            .select_from(ActionRequest)
            .where(ActionRequest.status.in_(["allowed", "approved", "completed"]))
        ).scalar()
        or 0
    )
    denied = (
        db.execute(
            select(func.count())
            .select_from(ActionRequest)
            .where(ActionRequest.status.in_(["denied", "rejected"]))
        ).scalar()
        or 0
    )
    pending = (
        db.execute(
            select(func.count()).select_from(ActionRequest).where(ActionRequest.status == "pending")
        ).scalar()
        or 0
    )
    escalated = (
        db.execute(
            select(func.count())
            .select_from(ActionRequest)
            .where(ActionRequest.status == "escalated")
        ).scalar()
        or 0
    )
    suspended = (
        db.execute(
            select(func.count()).select_from(Agent).where(Agent.status == "suspended")
        ).scalar()
        or 0
    )

    # avg approval time
    approved_rows = list(
        db.execute(
            select(ActionRequest).where(
                ActionRequest.decided_at.isnot(None),
                ActionRequest.created_at.isnot(None),
            )
        )
        .scalars()
        .all()
    )
    avg_secs = None
    if approved_rows:
        deltas = []
        for ar in approved_rows:
            if ar.decided_at and ar.created_at:
                deltas.append((ar.decided_at - ar.created_at).total_seconds())
        if deltas:
            avg_secs = int(sum(deltas) / len(deltas))

    needs = list(
        db.execute(
            select(ActionRequest)
            .where(ActionRequest.status.in_(["pending", "escalated"]))
            .order_by(ActionRequest.created_at.asc())
            .limit(8)
        )
        .scalars()
        .all()
    )
    agent_map = {a.id: a.name for a in db.execute(select(Agent)).scalars().all()}
    needs_attention = [
        {
            "id": ar.id,
            "agent_name": agent_map.get(ar.agent_id, "?"),
            "tool": ar.tool,
            "summary": ar.summary,
            "reason": ar.reason,
            "status": ar.status,
        }
        for ar in needs
    ]

    # Charts: last 7 days
    labels = []
    allow_s, deny_s, pend_s = [], [], []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        nxt = day + timedelta(days=1)
        labels.append(day.strftime("%m/%d"))
        rows = list(
            db.execute(
                select(ActionRequest).where(
                    ActionRequest.created_at >= day, ActionRequest.created_at < nxt
                )
            )
            .scalars()
            .all()
        )
        allow_s.append(
            sum(1 for r in rows if r.decision == "allow" or r.status in ("allowed", "approved"))
        )
        deny_s.append(
            sum(1 for r in rows if r.decision == "deny" or r.status in ("denied", "rejected"))
        )
        pend_s.append(sum(1 for r in rows if r.status in ("pending", "escalated")))

    by_agent: dict[str, int] = {}
    for ar in db.execute(select(ActionRequest)).scalars().all():
        name = agent_map.get(ar.agent_id, f"id-{ar.agent_id}")
        by_agent[name] = by_agent.get(name, 0) + 1

    head = ledger.get_head(db)
    return templates.TemplateResponse(
        request,
        "overview.html",
        _ctx(
            request,
            db,
            stats={
                "actions_today": actions_today,
                "allowed": allowed,
                "denied": denied,
                "pending": pending,
                "escalated": escalated,
                "suspended_agents": suspended,
                "avg_approval_seconds": avg_secs,
            },
            needs_attention=needs_attention,
            ledger_hash=head["last_hash"],
            ledger_seq=head["last_seq"],
            chart_time={"labels": labels, "allow": allow_s, "deny": deny_s, "pending": pend_s},
            chart_agent={
                "labels": list(by_agent.keys()) or ["none"],
                "values": list(by_agent.values()) or [0],
            },
        ),
    )


# ---------- Feed ----------


@router.get("/feed", response_class=HTMLResponse)
def feed_page(
    request: Request, db: Session = Depends(get_db), user: User = Depends(require_web_user)
):
    rows = _feed_rows(db)
    return templates.TemplateResponse(request, "feed.html", _ctx(request, db, rows=rows))


def _feed_rows(db: Session, limit: int = 50) -> list[dict]:
    rows = list(
        db.execute(select(ActionRequest).order_by(ActionRequest.created_at.desc()).limit(limit))
        .scalars()
        .all()
    )
    agents = {a.id: a.name for a in db.execute(select(Agent)).scalars().all()}
    out = []
    for ar in rows:
        params = ar.params or {}
        preview = ", ".join(f"{k}={v}" for k, v in list(params.items())[:3])
        out.append(
            {
                "id": ar.id,
                "created_at": ar.created_at,
                "agent_name": agents.get(ar.agent_id, "?"),
                "tool": ar.tool,
                "params_preview": preview,
                "decision": ar.decision,
                "status": ar.status,
                "matched_rule_id": ar.matched_rule_id,
            }
        )
    return out


@router.get("/partials/feed-rows", response_class=HTMLResponse)
def feed_rows_partial(
    request: Request, db: Session = Depends(get_db), user: User = Depends(require_web_user)
):
    return templates.TemplateResponse(
        request, "partials/feed_rows.html", _ctx(request, db, rows=_feed_rows(db))
    )


@router.get("/partials/action-detail/{action_id}", response_class=HTMLResponse)
def action_detail(
    action_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    ar = db.execute(select(ActionRequest).where(ActionRequest.id == action_id)).scalar_one_or_none()
    if ar is None:
        return HTMLResponse("Not found", status_code=404)
    agent = db.execute(select(Agent).where(Agent.id == ar.agent_id)).scalar_one_or_none()
    entries = list(
        db.execute(
            select(LedgerEntry)
            .where(
                LedgerEntry.subject_type == "action_request", LedgerEntry.subject_id == str(ar.id)
            )
            .order_by(LedgerEntry.seq.asc())
        )
        .scalars()
        .all()
    )
    timeline = []
    for e in entries:
        timeline.append(
            {
                "ts": e.ts.strftime("%Y-%m-%d %H:%M:%S") if e.ts else "",
                "event": e.event_type,
                "detail": json.dumps(e.payload)[:120] if e.payload else "",
            }
        )
    detail = {
        "agent_name": agent.name if agent else "?",
        "tool": ar.tool,
        "summary": ar.summary,
        "params": ar.params or {},
        "status": ar.status,
        "decision": ar.decision,
        "matched_rule_id": ar.matched_rule_id,
        "policy_version": ar.policy_version,
        "decision_reason": ar.decision_reason,
    }
    return templates.TemplateResponse(
        request,
        "partials/action_detail.html",
        _ctx(request, db, ar=detail, timeline=timeline),
    )


@router.get("/partials/ledger-badge", response_class=HTMLResponse)
def ledger_badge(
    request: Request, db: Session = Depends(get_db), user: User = Depends(require_web_user)
):
    result = ledger.verify(db)
    head = ledger.get_head(db)
    return templates.TemplateResponse(
        request,
        "partials/ledger_badge.html",
        _ctx(
            request,
            db,
            ok=result["ok"],
            seq=head["last_seq"],
            short_hash=(head["last_hash"] or "")[:8],
            broken_seq=result.get("first_broken_seq"),
        ),
    )


# ---------- Approvals ----------


@router.get("/approvals", response_class=HTMLResponse)
def approvals_page(
    request: Request,
    tab: str = "pending",
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    status_filter = "escalated" if tab == "escalated" else "pending"
    rows = list(
        db.execute(
            select(ActionRequest)
            .where(ActionRequest.status == status_filter)
            .order_by(ActionRequest.created_at.asc())
        )
        .scalars()
        .all()
    )
    agents = {a.id: a for a in db.execute(select(Agent)).scalars().all()}
    now = datetime.now(UTC)
    items = []
    for ar in rows:
        agent = agents.get(ar.agent_id)
        sla_rem = None
        if ar.sla_deadline:
            dl = ar.sla_deadline if ar.sla_deadline.tzinfo else ar.sla_deadline.replace(tzinfo=UTC)
            sla_rem = max(0, int((dl - now).total_seconds()))
        items.append(
            {
                "id": ar.id,
                "agent_name": agent.name if agent else "?",
                "tool": ar.tool,
                "summary": ar.summary,
                "status": ar.status,
                "created_at": ar.created_at.strftime("%Y-%m-%d %H:%M") if ar.created_at else "",
                "amount": (ar.params or {}).get("amount"),
                "sensitivity": ar.sensitivity,
                "sla_remaining": sla_rem,
                "is_owner": agent is not None and agent.owner_user_id == user.id,
            }
        )
    pending_count = (
        db.execute(
            select(func.count()).select_from(ActionRequest).where(ActionRequest.status == "pending")
        ).scalar()
        or 0
    )
    escalated_count = (
        db.execute(
            select(func.count())
            .select_from(ActionRequest)
            .where(ActionRequest.status == "escalated")
        ).scalar()
        or 0
    )
    return templates.TemplateResponse(
        request,
        "approvals.html",
        _ctx(
            request,
            db,
            items=items,
            tab=tab,
            pending_count=pending_count,
            escalated_count=escalated_count,
        ),
    )


@router.post("/approvals/{action_id}/approve")
def web_approve(
    action_id: int,
    request: Request,
    reason: str = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role == "auditor":
        return RedirectResponse("/approvals?toast=Auditors+are+read-only", status_code=303)
    try:
        approvals_svc.approve(db, action_id, user, reason)
        db.commit()
    except ApprovalError as e:
        db.rollback()
        return RedirectResponse(f"/approvals?toast={e.message}", status_code=303)
    return RedirectResponse("/approvals?toast=Approved", status_code=303)


@router.post("/approvals/{action_id}/reject")
def web_reject(
    action_id: int,
    request: Request,
    reason: str = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role == "auditor":
        return RedirectResponse("/approvals?toast=Auditors+are+read-only", status_code=303)
    try:
        approvals_svc.reject(db, action_id, user, reason)
        db.commit()
    except ApprovalError as e:
        db.rollback()
        return RedirectResponse(f"/approvals?toast={e.message}", status_code=303)
    return RedirectResponse("/approvals?toast=Rejected", status_code=303)


# ---------- Agents ----------


@router.get("/agents", response_class=HTMLResponse)
def agents_page(
    request: Request, db: Session = Depends(get_db), user: User = Depends(require_web_user)
):
    agents_rows = list(db.execute(select(Agent).order_by(Agent.id)).scalars().all())
    users = {u.id: u for u in db.execute(select(User)).scalars().all()}
    agents = []
    for a in agents_rows:
        cnt = (
            db.execute(
                select(func.count())
                .select_from(ActionRequest)
                .where(ActionRequest.agent_id == a.id)
            ).scalar()
            or 0
        )
        owner = users.get(a.owner_user_id)
        agents.append(
            {
                "id": a.id,
                "name": a.name,
                "purpose": a.purpose,
                "owner_name": owner.name if owner else "?",
                "risk_tier": a.risk_tier,
                "status": a.status,
                "request_count": cnt,
                "api_key_prefix": a.api_key_prefix,
            }
        )
    return templates.TemplateResponse(request, "agents.html", _ctx(request, db, agents=agents))


@router.get("/agents/new", response_class=HTMLResponse)
def agent_new_page(
    request: Request, db: Session = Depends(get_db), user: User = Depends(require_web_user)
):
    if user.role != "admin":
        return RedirectResponse("/agents", status_code=303)
    owners = list(db.execute(select(User).where(User.is_active.is_(True))).scalars().all())
    return templates.TemplateResponse(request, "agent_new.html", _ctx(request, db, owners=owners))


@router.post("/agents/new")
def agent_create(
    request: Request,
    name: str = Form(...),
    purpose: str = Form(""),
    owner_user_id: int = Form(...),
    risk_tier: str = Form("medium"),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role != "admin":
        return RedirectResponse("/agents", status_code=303)
    full, prefix, key_hash = generate_api_key()
    agent = Agent(
        name=name.strip(),
        purpose=purpose,
        owner_user_id=owner_user_id,
        risk_tier=risk_tier,
        status="active",
        api_key_prefix=prefix,
        api_key_hash=key_hash,
    )
    db.add(agent)
    db.flush()
    ledger.append(
        db,
        event_type="agent_registered",
        actor_type="user",
        actor_id=str(user.id),
        subject_type="agent",
        subject_id=str(agent.id),
        payload={"name": agent.name},
    )
    db.commit()
    db.refresh(agent)
    return templates.TemplateResponse(
        request, "agent_created.html", _ctx(request, db, agent=agent, api_key=full)
    )


@router.post("/agents/{agent_id}/suspend")
def web_suspend(
    agent_id: int,
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role != "admin":
        return RedirectResponse("/agents", status_code=303)
    agent = db.execute(select(Agent).where(Agent.id == agent_id)).scalar_one_or_none()
    if agent:
        suspend_agent(db, agent, by=str(user.id))
        db.commit()
    return RedirectResponse("/agents?toast=Agent+suspended", status_code=303)


@router.post("/agents/{agent_id}/resume")
def web_resume(
    agent_id: int,
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role != "admin":
        return RedirectResponse("/agents", status_code=303)
    agent = db.execute(select(Agent).where(Agent.id == agent_id)).scalar_one_or_none()
    if agent:
        resume_agent(db, agent, by=str(user.id))
        db.commit()
    return RedirectResponse("/agents?toast=Agent+resumed", status_code=303)


@router.get("/agents/{agent_id}", response_class=HTMLResponse)
def agent_detail(
    agent_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    agent = db.execute(select(Agent).where(Agent.id == agent_id)).scalar_one_or_none()
    if agent is None:
        return templates.TemplateResponse(request, "404.html", _ctx(request, db), status_code=404)
    owner = db.execute(select(User).where(User.id == agent.owner_user_id)).scalar_one_or_none()
    actions = list(
        db.execute(
            select(ActionRequest)
            .where(ActionRequest.agent_id == agent_id)
            .order_by(ActionRequest.created_at.desc())
            .limit(50)
        )
        .scalars()
        .all()
    )
    stats = {
        "total": len(actions),
        "allowed": sum(1 for a in actions if a.status in ("allowed", "approved", "completed")),
        "denied": sum(1 for a in actions if a.status in ("denied", "rejected")),
    }
    timeline = [
        {
            "ts": a.created_at.strftime("%Y-%m-%d %H:%M:%S") if a.created_at else "",
            "tool": a.tool,
            "decision": a.decision,
            "status": a.status,
            "reason": a.reason or a.decision_reason or "",
        }
        for a in actions
    ]
    return templates.TemplateResponse(
        request,
        "agent_detail.html",
        _ctx(request, db, agent=agent, owner=owner, stats=stats, timeline=timeline),
    )


# ---------- Policies ----------


DEFAULT_POLICY = {
    "default_effect": "deny",
    "rules": [
        {
            "id": "refund-small-auto",
            "priority": 10,
            "description": "Refunds up to 100 auto-approved",
            "match": {"agents": ["refund-bot"], "tools": ["issue_refund"]},
            "conditions": [{"type": "amount_lte", "field": "amount", "value": 100}],
            "effect": "allow",
        }
    ],
}


@router.get("/policies", response_class=HTMLResponse)
def policies_page(
    request: Request, db: Session = Depends(get_db), user: User = Depends(require_web_user)
):
    active = db.execute(select(Policy).where(Policy.is_active.is_(True))).scalar_one_or_none()
    versions = list(db.execute(select(Policy).order_by(Policy.version.desc())).scalars().all())
    return templates.TemplateResponse(
        request,
        "policies.html",
        _ctx(
            request,
            db,
            active=active,
            versions=versions,
            default_policy_json=json.dumps(DEFAULT_POLICY, indent=2),
            policy_error=None,
            sim=None,
        ),
    )


@router.post("/policies/create")
async def policy_create(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    form = await request.form()
    csrf_token = form.get("csrf_token", "")
    verify_csrf(request, str(csrf_token))
    if user.role != "admin":
        return RedirectResponse("/policies", status_code=303)
    rules_json = str(form.get("rules_json", "{}"))
    note = str(form.get("note") or "")
    action = str(form.get("action", "create"))
    try:
        rules = json.loads(rules_json)
    except json.JSONDecodeError as e:
        active = db.execute(select(Policy).where(Policy.is_active.is_(True))).scalar_one_or_none()
        versions = list(db.execute(select(Policy).order_by(Policy.version.desc())).scalars().all())
        return templates.TemplateResponse(
            request,
            "policies.html",
            _ctx(
                request,
                db,
                active=active,
                versions=versions,
                default_policy_json=rules_json,
                policy_error=f"Invalid JSON: {e}",
                sim=None,
            ),
        )
    errors = validate_policy(rules)
    if errors:
        active = db.execute(select(Policy).where(Policy.is_active.is_(True))).scalar_one_or_none()
        versions = list(db.execute(select(Policy).order_by(Policy.version.desc())).scalars().all())
        return templates.TemplateResponse(
            request,
            "policies.html",
            _ctx(
                request,
                db,
                active=active,
                versions=versions,
                default_policy_json=rules_json,
                policy_error="; ".join(errors),
                sim=None,
            ),
        )
    if action == "simulate":
        sim = simulate(db, rules, last_n=50)
        active = db.execute(select(Policy).where(Policy.is_active.is_(True))).scalar_one_or_none()
        versions = list(db.execute(select(Policy).order_by(Policy.version.desc())).scalars().all())
        return templates.TemplateResponse(
            request,
            "policies.html",
            _ctx(
                request,
                db,
                active=active,
                versions=versions,
                default_policy_json=rules_json,
                policy_error=None,
                sim=sim,
            ),
        )
    max_v = db.execute(select(Policy.version).order_by(Policy.version.desc()).limit(1)).scalar()
    version = (max_v or 0) + 1
    p = Policy(version=version, rules=rules, is_active=False, created_by=user.id, note=note)
    db.add(p)
    db.flush()
    ledger.append(
        db,
        event_type="policy_created",
        actor_type="user",
        actor_id=str(user.id),
        subject_type="policy",
        subject_id=str(p.id),
        payload={"version": version},
        policy_version=version,
    )
    db.commit()
    return RedirectResponse(f"/policies?toast=Policy+v{version}+created", status_code=303)


@router.post("/policies/{policy_id}/activate")
def policy_activate(
    policy_id: int,
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role != "admin":
        return RedirectResponse("/policies", status_code=303)
    p = db.execute(select(Policy).where(Policy.id == policy_id)).scalar_one_or_none()
    if p:
        for other in db.execute(select(Policy).where(Policy.is_active.is_(True))).scalars().all():
            other.is_active = False
        p.is_active = True
        ledger.append(
            db,
            event_type="policy_activated",
            actor_type="user",
            actor_id=str(user.id),
            subject_type="policy",
            subject_id=str(p.id),
            payload={"version": p.version},
            policy_version=p.version,
        )
        db.commit()
    return RedirectResponse("/policies?toast=Policy+activated", status_code=303)


# ---------- Ledger ----------


@router.get("/ledger", response_class=HTMLResponse)
def ledger_page(
    request: Request, db: Session = Depends(get_db), user: User = Depends(require_web_user)
):
    entries = list(
        db.execute(select(LedgerEntry).order_by(LedgerEntry.seq.desc()).limit(100)).scalars().all()
    )
    head = ledger.get_head(db)
    entry_dicts = [
        {
            "seq": e.seq,
            "ts": e.ts.strftime("%Y-%m-%d %H:%M:%S") if e.ts else "",
            "event_type": e.event_type,
            "actor_type": e.actor_type,
            "actor_id": e.actor_id,
            "hash": e.hash,
            "prev_hash": e.prev_hash,
        }
        for e in entries
    ]
    return templates.TemplateResponse(
        request,
        "ledger.html",
        _ctx(request, db, entries=entry_dicts, head=head, verify_result=None),
    )


@router.post("/ledger/verify")
def web_ledger_verify(
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    result = ledger.verify(db)
    entries = list(
        db.execute(select(LedgerEntry).order_by(LedgerEntry.seq.desc()).limit(100)).scalars().all()
    )
    head = ledger.get_head(db)
    entry_dicts = [
        {
            "seq": e.seq,
            "ts": e.ts.strftime("%Y-%m-%d %H:%M:%S") if e.ts else "",
            "event_type": e.event_type,
            "actor_type": e.actor_type,
            "actor_id": e.actor_id,
            "hash": e.hash,
            "prev_hash": e.prev_hash,
        }
        for e in entries
    ]
    return templates.TemplateResponse(
        request,
        "ledger.html",
        _ctx(request, db, entries=entry_dicts, head=head, verify_result=result),
    )


@router.get("/ledger/export")
def web_ledger_export(
    request: Request,
    fmt: str = "json",
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    from app.api.ledger_api import export_ledger

    return export_ledger(fmt=fmt, user=user, db=db)


@router.post("/ledger/checkpoint")
def web_checkpoint(
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    cp = ledger.create_checkpoint(db)
    db.commit()
    return JSONResponse(cp)


# ---------- System freeze ----------


@router.post("/system/freeze")
def web_freeze(
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role == "admin":
        freeze_system(db, by=str(user.id), note="web freeze")
        db.commit()
    return RedirectResponse("/agents?toast=System+frozen", status_code=303)


@router.post("/system/unfreeze")
def web_unfreeze(
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role == "admin":
        unfreeze_system(db, by=str(user.id))
        db.commit()
    return RedirectResponse("/agents?toast=System+unfrozen", status_code=303)


# ---------- Demo Lab (DEMO_MODE + admin) ----------


@router.get("/demo-lab", response_class=HTMLResponse)
def demo_lab_page(
    request: Request, db: Session = Depends(get_db), user: User = Depends(require_web_user)
):
    settings = get_settings()
    if not settings.demo_mode or user.role != "admin":
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "demo_lab.html", _ctx(request, db))


@router.post("/demo-lab/run/{scenario}")
def demo_lab_run(
    scenario: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    settings = get_settings()
    if not settings.demo_mode or user.role != "admin":
        return JSONResponse({"error": "forbidden"}, status_code=403)
    # CSRF via header
    verify_csrf(request, request.headers.get("X-CSRF-Token"))

    from app.services import actions as actions_svc
    from app.services.approvals import ApprovalError, approve
    from scripts.tamper import repair, tamper

    refund = db.execute(select(Agent).where(Agent.name == "refund-bot")).scalar_one_or_none()
    if refund is None:
        return JSONResponse({"error": "refund-bot not found – run seed"}, status_code=400)

    if scenario == "small":
        ar = actions_svc.request_action(
            db, agent=refund, tool="issue_refund", params={"amount": 40}, sensitivity="internal"
        )
        db.commit()
        return {"id": ar.id, "decision": ar.decision, "status": ar.status, "reason": ar.reason}

    if scenario == "large":
        ar = actions_svc.request_action(
            db, agent=refund, tool="issue_refund", params={"amount": 900}, sensitivity="internal"
        )
        db.commit()
        return {
            "id": ar.id,
            "decision": ar.decision,
            "status": ar.status,
            "message": "Go to Approvals as reviewer_b to approve",
        }

    if scenario == "leak":
        ar = actions_svc.request_action(
            db,
            agent=refund,
            tool="send_email",
            params={"to": "evil@gmail.com", "subject": "Customer Export"},
            sensitivity="pii",
        )
        db.commit()
        return {
            "id": ar.id,
            "decision": ar.decision,
            "status": ar.status,
            "rule": ar.matched_rule_id,
        }

    if scenario == "burst":
        results = []
        for i in range(12):
            ar = actions_svc.request_action(
                db, agent=refund, tool="issue_refund", params={"amount": 5}, sensitivity="internal"
            )
            results.append({"id": ar.id, "decision": ar.decision})
        db.commit()
        return {"results": results}

    if scenario == "overdue":
        ar = actions_svc.request_action(
            db,
            agent=refund,
            tool="issue_refund",
            params={"amount": 250},
            sensitivity="internal",
            sla_override_seconds=45,
        )
        db.commit()
        return {
            "id": ar.id,
            "decision": ar.decision,
            "status": ar.status,
            "sla_deadline": ar.sla_deadline.isoformat() if ar.sla_deadline else None,
            "message": "Watch Approvals escalated tab in ~45s",
        }

    if scenario == "self":
        ar = actions_svc.request_action(
            db, agent=refund, tool="issue_refund", params={"amount": 400}, sensitivity="internal"
        )
        db.commit()
        owner = db.execute(select(User).where(User.id == refund.owner_user_id)).scalar_one()
        try:
            approve(db, ar.id, owner, "Trying to self-approve as owner which should fail")
            db.commit()
            return {"error": "unexpected success"}
        except ApprovalError as e:
            db.rollback()
            return {"blocked": True, "code": e.code, "message": e.message, "action_id": ar.id}

    if scenario == "tamper":
        tamper()
        return {"message": "Ledger row tampered. Go to Ledger and click Verify."}

    if scenario == "repair":
        repair()
        return {"message": "Tamper repaired. Verify should PASS again."}

    return JSONResponse({"error": f"unknown scenario {scenario}"}, status_code=400)
