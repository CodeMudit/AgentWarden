from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import ledger
from app.api.activity_api import redact_params
from app.config import get_settings
from app.db import get_db
from app.models import (
    ActionRequest,
    Agent,
    Incident,
    LedgerEntry,
    Policy,
    User,
)
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
from app.services.approvals import ApprovalError, approve
from app.services.incidents import (
    IncidentError,
    get_accountability_chain,
    open_incident,
    resolve_incident,
)
from app.services.killswitch import (
    freeze_system,
    get_system_state,
    pause_agent,
    restrict_agent,
    resume_agent,
    suspend_agent,
    unfreeze_system,
)
from app.services.work_allocation import get_allocation_metrics

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
        "params_hash": getattr(ar, "params_hash", None),
        "status": ar.status,
        "decision": ar.decision,
        "matched_rule_id": ar.matched_rule_id,
        "policy_version": ar.policy_version,
        "decision_reason": ar.decision_reason,
        "trace": ar.evaluation_trace,
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
        owner_name = None
        if agent is not None:
            from app.models import User as _User
            ou = db.execute(select(_User).where(_User.id == agent.owner_user_id)).scalar_one_or_none()
            owner_name = ou.name if ou else None
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
                "params": ar.params or {},
                "params_hash": getattr(ar, "params_hash", None),
                "matched_rule_id": ar.matched_rule_id,
                "owner_name": owner_name,
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
    reason: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role == "auditor":
        return RedirectResponse("/approvals?toast=Auditors+are+read-only", status_code=303)
    if len(reason.strip()) < 10:
        return RedirectResponse("/approvals?toast=Reason+must+be+at+least+10+characters", status_code=303)
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
    reason: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role == "auditor":
        return RedirectResponse("/approvals?toast=Auditors+are+read-only", status_code=303)
    if len(reason.strip()) < 10:
        return RedirectResponse("/approvals?toast=Reason+must+be+at+least+10+characters", status_code=303)
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
    permitted_actions_csv: str = Form(""),
    data_access_csv: str = Form(""),
    cost_per_call: float = Form(0.01),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role != "admin":
        return RedirectResponse("/agents", status_code=303)

    clean_name = name.strip()
    existing = db.execute(select(Agent).where(Agent.name == clean_name)).scalar_one_or_none()
    if existing:
        owners = list(db.execute(select(User).where(User.is_active.is_(True))).scalars().all())
        return templates.TemplateResponse(
            request,
            "agent_new.html",
            _ctx(request, db, owners=owners, error=f"Agent '{clean_name}' already exists. Please choose a unique name."),
            status_code=400,
        )

    permitted = [a.strip() for a in permitted_actions_csv.split(",") if a.strip()]
    scopes = [s.strip() for s in data_access_csv.split(",") if s.strip()]

    full, prefix, key_hash = generate_api_key()
    agent = Agent(
        name=clean_name,
        purpose=purpose,
        owner_user_id=owner_user_id,
        risk_tier=risk_tier,
        risk_category=risk_tier,
        permitted_actions=permitted,
        data_access=scopes,
        cost_per_call=cost_per_call,
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
        payload={
            "name": agent.name,
            "risk_category": risk_tier,
            "permitted_actions": permitted,
            "data_access": scopes,
            "cost_per_call": cost_per_call,
        },
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
    from app.services.approvals import ApprovalError
    from scripts.tamper import repair, tamper

    refund = db.execute(select(Agent).where(Agent.name == "refund-bot")).scalar_one_or_none()
    if refund is None:
        return JSONResponse({"error": "refund-bot not found – run seed"}, status_code=400)

    if scenario in ("small", "allow"):
        ar = actions_svc.request_action(
            db, agent=refund, tool="issue_refund", params={"amount": 40}, sensitivity="internal"
        )
        db.commit()
        return {"id": ar.id, "decision": ar.decision, "status": ar.status, "reason": ar.reason}

    if scenario in ("large", "pending"):
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

    if scenario in ("leak", "deny"):
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

    if scenario in ("overdue", "escalate"):
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
            approvals_svc.approve(db, ar.id, owner, "Trying to self-approve as owner which should fail")
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

    if scenario == "injection":
        ar = actions_svc.request_action(
            db,
            agent=refund,
            tool="issue_refund",
            params={
                "amount": 5000,
                "order_id": "ORD-7781",
                "source": "customer_email",
                "note": "Hidden instruction in email tried to force refund",
            },
            sensitivity="internal",
            context={"attack_demo": True, "injection_present": True},
        )
        db.commit()
        return {
            "story": "Customer email hid: ignore rules and refund $5000",
            "id": ar.id,
            "decision": ar.decision,
            "status": ar.status,
            "rule": ar.matched_rule_id,
            "reason": ar.reason,
            "message": "Attack blocked or held — money did not move automatically",
        }

    if scenario == "simulate":
        draft = {
            "default_effect": "deny",
            "rules": [
                {
                    "id": "refund-small-auto",
                    "priority": 10,
                    "match": {"agents": ["refund-bot"], "tools": ["issue_refund"]},
                    "conditions": [{"type": "amount_lte", "field": "amount", "value": 50}],
                    "effect": "allow",
                },
                {
                    "id": "refund-large-review",
                    "priority": 20,
                    "match": {"agents": ["refund-bot"], "tools": ["issue_refund"]},
                    "conditions": [{"type": "amount_gt", "field": "amount", "value": 50}],
                    "effect": "require_approval",
                },
            ],
        }
        sim = simulate(db, draft, last_n=50)
        return {
            "message": "What if auto-allow threshold dropped from 100 to 50?",
            "simulation": sim,
        }

<<<<<<< HEAD
=======
    if scenario == "ps5_governance":
        # Step 1: Ensure agent is active for the test
        if refund.status == "paused":
            resume_agent(db, refund, by=str(user.id), reason="Resetting for PS5 governance demo")
            db.commit()
            db.refresh(refund)

        # Step 2: Agent attempts an unpermitted tool call (export_customer_pii) with sensitive data
        ar1 = actions_svc.request_action(
            db,
            agent=refund,
            tool="export_customer_pii",
            params={"customer_id": "CUST-9912", "fields": ["ssn", "cc_number"]},
            sensitivity="restricted",
            data_used=["restricted:ssn", "restricted:cc_number"],
        )
        db.commit()
        db.refresh(refund)
        breach_caught = getattr(ar1, "is_breach", False) or ar1.decision == "deny"
        breach_error_message = ar1.reason or "Policy breach detected"

        # Step 3: Verify agent was automatically paused
        agent_auto_paused = (refund.status == "paused")

        # Step 4: Verify subsequent actions are immediately denied due to paused state
        ar2 = actions_svc.request_action(
            db,
            agent=refund,
            tool="issue_refund",
            params={"amount": 25},
            sensitivity="internal",
        )
        db.commit()
        subsequent_denied = (ar2.decision == "deny" and "paused" in (ar2.reason or "").lower())

        # Step 5: Query the Incident created for this breach
        inc = db.execute(
            select(Incident).where(Incident.agent_id == refund.id).order_by(Incident.created_at.desc())
        ).scalars().first()

        return {
            "story": "PS5 Demo: Refund Bot attempted unpermitted action 'export_customer_pii' on restricted PII data.",
            "policy_breach_detected": breach_caught,
            "breach_message": breach_error_message,
            "agent_auto_paused": agent_auto_paused,
            "subsequent_action_blocked": subsequent_denied,
            "incident_id": inc.id if inc else None,
            "incident_severity": inc.severity if inc else None,
            "message": "Policy breach detected! Agent automatically PAUSED, incident opened, and all subsequent calls blocked.",
            "next_step": "Visit Incidents page to view the full accountability chain or Agent page to resume with authorization.",
        }

>>>>>>> a981b25 (New Updates)
    return JSONResponse({"error": f"unknown scenario {scenario}"}, status_code=400)


@router.post("/ledger/verify-json")
def web_ledger_verify_json(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, request.headers.get("X-CSRF-Token"))
    result = ledger.verify(db)
    return JSONResponse(result)


@router.get("/partials/approvals-list", response_class=HTMLResponse)
def approvals_list_partial(
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
        owner_name = None
        if agent is not None:
            from app.models import User as _User
            ou = db.execute(select(_User).where(_User.id == agent.owner_user_id)).scalar_one_or_none()
            owner_name = ou.name if ou else None
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
                "params": ar.params or {},
                "params_hash": getattr(ar, "params_hash", None),
                "matched_rule_id": ar.matched_rule_id,
                "owner_name": owner_name,
            }
        )
    return templates.TemplateResponse(
        request,
        "partials/approvals_list.html",
        _ctx(request, db, items=items, tab=tab),
    )


<<<<<<< HEAD
=======
@router.get("/activity", response_class=HTMLResponse)
def activity_trail_page(
    request: Request,
    agent_id: str | None = None,
    decision: str | None = None,
    risk_category: str | None = None,
    outcome: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    all_agents = list(db.execute(select(Agent).order_by(Agent.name.asc())).scalars().all())
    agents_map = {a.id: a for a in all_agents}
    users_map = {u.id: u for u in db.execute(select(User)).scalars().all()}

    query = select(ActionRequest).order_by(ActionRequest.created_at.desc())
    if agent_id:
        try:
            aid = int(agent_id)
            query = query.where(ActionRequest.agent_id == aid)
        except ValueError:
            pass

    if decision:
        query = query.where(ActionRequest.decision == decision)

    if outcome:
        query = query.where(ActionRequest.status == outcome)

    actions = list(db.execute(query.limit(100)).scalars().all())

    if risk_category:
        filtered = []
        for ar in actions:
            ag = agents_map.get(ar.agent_id)
            if ag and (ag.risk_category == risk_category or getattr(ag, "risk_tier", None) == risk_category):
                filtered.append(ar)
        actions = filtered

    action_ids = [ar.id for ar in actions]
    ledger_entries = list(
        db.execute(
            select(LedgerEntry).where(
                LedgerEntry.event_type.in_([
                    "action_evaluated",
                    "action_allowed",
                    "action_denied",
                    "policy_breach_detected",
                    "action_completed",
                    "action_approved",
                    "action_rejected",
                ])
            )
        ).scalars().all()
    )
    action_seq_map: dict[int, int] = {}
    for entry in ledger_entries:
        try:
            payload = json.loads(entry.payload_json) if isinstance(entry.payload_json, str) else entry.payload_json
            aid = payload.get("action_id")
            if aid in action_ids and aid not in action_seq_map:
                action_seq_map[aid] = entry.seq
        except Exception:
            pass

    items = []
    for ar in actions:
        ag = agents_map.get(ar.agent_id)
        owner_name = None
        if ag:
            ou = users_map.get(ag.owner_user_id)
            owner_name = ou.name if ou else "Unknown Owner"

        decided_by_user = users_map.get(ar.decided_by) if ar.decided_by else None

        items.append({
            "id": ar.id,
            "created_at": ar.created_at.strftime("%Y-%m-%d %H:%M:%S") if ar.created_at else "",
            "tool": ar.tool,
            "is_breach": getattr(ar, "is_breach", False),
            "breach_reason": getattr(ar, "breach_reason", None),
            "agent": {
                "id": ag.id if ag else 0,
                "name": ag.name if ag else "Unknown Agent",
                "risk_category": ag.risk_category if ag else "medium",
                "owner_name": owner_name,
            },
            "data_used": getattr(ar, "data_used", None) or [],
            "matched_rule_id": ar.matched_rule_id,
            "decision": ar.decision or ar.status,
            "decided_by_name": decided_by_user.name if decided_by_user else None,
            "decision_reason": ar.decision_reason or ar.reason,
            "status": ar.status,
            "ledger_seq": action_seq_map.get(ar.id),
        })

    params_dict = {}
    if agent_id:
        params_dict["agent_id"] = agent_id
    if decision:
        params_dict["decision"] = decision
    if risk_category:
        params_dict["risk_category"] = risk_category
    if outcome:
        params_dict["outcome"] = outcome
    querystring = "&".join(f"{k}={v}" for k, v in params_dict.items())

    return templates.TemplateResponse(
        request,
        "activity.html",
        _ctx(
            request,
            db,
            items=items,
            all_agents=all_agents,
            count=len(items),
            querystring=querystring,
            filters={
                "agent_id": agent_id or "",
                "decision": decision or "",
                "risk_category": risk_category or "",
                "outcome": outcome or "",
            },
        ),
    )


@router.get("/leadership", response_class=HTMLResponse)
def leadership_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    agents = list(db.execute(select(Agent).order_by(Agent.name.asc())).scalars().all())
    users_map = {u.id: u for u in db.execute(select(User)).scalars().all()}
    actions = list(db.execute(select(ActionRequest)).scalars().all())
    incidents = list(db.execute(select(Incident)).scalars().all())

    total_agents = len(agents)
    active_agents = sum(1 for a in agents if a.status == "active")
    restricted_agents = sum(1 for a in agents if a.status == "restricted")
    paused_agents = sum(1 for a in agents if a.status == "paused")

    total_breaches = sum(a.breach_count for a in agents) + sum(1 for ar in actions if getattr(ar, "is_breach", False))
    open_incidents = sum(1 for inc in incidents if inc.status in ("open", "investigating"))

    total_requests = len(actions)

    agent_counts: dict[int, int] = {}
    for ar in actions:
        agent_counts[ar.agent_id] = agent_counts.get(ar.agent_id, 0) + 1

    total_cost = 0.0
    for a in agents:
        c = (agent_counts.get(a.id, 0)) * (a.cost_per_call or 0.0)
        total_cost += c

    automated_actions = sum(1 for ar in actions if ar.status in ("allowed", "completed"))
    hours_saved = automated_actions * 0.2
    dollars_saved = hours_saved * 45.0

    risk_counts = {
        "low": sum(1 for a in agents if (a.risk_category == "low" or getattr(a, "risk_tier", "") == "low")),
        "medium": sum(1 for a in agents if (a.risk_category == "medium" or getattr(a, "risk_tier", "") == "medium")),
        "high": sum(1 for a in agents if (a.risk_category == "high" or getattr(a, "risk_tier", "") == "high")),
        "critical": sum(1 for a in agents if (a.risk_category == "critical" or getattr(a, "risk_tier", "") == "critical")),
    }

    decisions = {
        "allow": sum(1 for ar in actions if ar.decision == "allow" or ar.status in ("allowed", "completed")),
        "require_approval": sum(1 for ar in actions if ar.decision == "require_approval" or ar.status in ("pending", "escalated", "approved", "rejected")),
        "deny": sum(1 for ar in actions if ar.decision == "deny" or ar.status in ("denied", "failed")),
    }

    allocation_metrics = get_allocation_metrics(db)

    stats = {
        "total_agents": total_agents,
        "active_agents": active_agents,
        "restricted_agents": restricted_agents,
        "paused_agents": paused_agents,
        "total_breaches": total_breaches,
        "open_incidents": open_incidents,
        "total_cost": total_cost,
        "total_requests": total_requests,
        "hours_saved": hours_saved,
        "dollars_saved": dollars_saved,
        "risk_counts": risk_counts,
        "allocation": {
            "human_pct": allocation_metrics["human_allocated_pct"],
            "agent_pct": allocation_metrics["agent_allocated_pct"],
        },
        "decisions": decisions,
    }

    agent_rows = []
    for a in agents:
        ou = users_map.get(a.owner_user_id)
        req_count = agent_counts.get(a.id, 0)
        agent_cost = req_count * (a.cost_per_call or 0.0)
        agent_rows.append({
            "id": a.id,
            "name": a.name,
            "owner_name": ou.name if ou else "Unknown",
            "risk_category": a.risk_category,
            "status": a.status,
            "permitted_actions": a.permitted_actions or [],
            "data_access": a.data_access or [],
            "request_count": req_count,
            "cost_accrued": agent_cost,
            "total_cost": agent_cost,
            "breach_count": a.breach_count,
        })

    return templates.TemplateResponse(
        request,
        "leadership.html",
        _ctx(
            request,
            db,
            stats=stats,
            agent_rows=agent_rows,
        ),
    )


@router.post("/agents/{agent_id}/pause")
def web_agent_pause(
    request: Request,
    agent_id: int,
    reason: str = Form("Manual pause by operator"),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role not in ("admin", "reviewer"):
        raise HTTPException(status_code=403, detail="Forbidden: Admin or Reviewer role required")
    agent = db.execute(select(Agent).where(Agent.id == agent_id)).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    pause_agent(db, agent, by=str(user.id), reason=reason or "Manual pause by operator")
    db.commit()
    referer = request.headers.get("Referer") or f"/agents/{agent_id}"
    return RedirectResponse(referer, status_code=303)


@router.post("/agents/{agent_id}/restrict")
def web_agent_restrict(
    request: Request,
    agent_id: int,
    reason: str = Form("Manual restriction by operator"),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role not in ("admin", "reviewer"):
        raise HTTPException(status_code=403, detail="Forbidden: Admin or Reviewer role required")
    agent = db.execute(select(Agent).where(Agent.id == agent_id)).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    restrict_agent(db, agent, by=str(user.id), reason=reason or "Manual restriction by operator")
    db.commit()
    referer = request.headers.get("Referer") or f"/agents/{agent_id}"
    return RedirectResponse(referer, status_code=303)


@router.post("/agents/{agent_id}/resume")
def web_agent_resume(
    request: Request,
    agent_id: int,
    reason: str = Form("Manual resume by admin"),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: Admin role required to resume agent")
    agent = db.execute(select(Agent).where(Agent.id == agent_id)).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    resume_agent(db, agent, by=str(user.id), reason=reason or "Manual resume by admin")
    db.commit()
    referer = request.headers.get("Referer") or f"/agents/{agent_id}"
    return RedirectResponse(referer, status_code=303)


@router.get("/incidents", response_class=HTMLResponse)
def incidents_list_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    incidents = list(db.execute(select(Incident).order_by(Incident.created_at.desc())).scalars().all())
    agents_map = {a.id: a for a in db.execute(select(Agent)).scalars().all()}
    users_map = {u.id: u for u in db.execute(select(User)).scalars().all()}

    open_count = sum(1 for i in incidents if i.status == "open")
    investigating_count = sum(1 for i in incidents if i.status == "investigating")
    resolved_count = sum(1 for i in incidents if i.status == "resolved")

    stats = {
        "open": open_count,
        "investigating": investigating_count,
        "resolved": resolved_count,
    }

    inc_items = []
    for inc in incidents:
        ag = agents_map.get(inc.agent_id) if inc.agent_id else None
        assignee = users_map.get(inc.assigned_user_id) if inc.assigned_user_id else None
        inc_items.append({
            "id": inc.id,
            "title": inc.title,
            "description": inc.description,
            "severity": inc.severity,
            "status": inc.status,
            "agent_name": ag.name if ag else None,
            "owner_name": assignee.name if assignee else (users_map.get(ag.owner_user_id).name if ag and ag.owner_user_id in users_map else None),
            "created_at": inc.created_at.strftime("%Y-%m-%d %H:%M") if inc.created_at else "",
        })

    all_agents = list(db.execute(select(Agent).order_by(Agent.name.asc())).scalars().all())

    return templates.TemplateResponse(
        request,
        "incidents.html",
        _ctx(
            request,
            db,
            stats=stats,
            incidents=inc_items,
            all_agents=all_agents,
        ),
    )


@router.post("/incidents")
def create_incident_form(
    request: Request,
    title: str = Form(...),
    description: str = Form(...),
    severity: str = Form("medium"),
    agent_id: int | None = Form(None),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role not in ("admin", "reviewer"):
        return RedirectResponse("/incidents?toast=Auditors+cannot+file+incidents", status_code=303)

    open_incident(
        db,
        title=title,
        description=description,
        creator_user=user,
        agent_id=agent_id,
        action_request_id=None,
        severity=severity,
        assigned_user_id=user.id,
    )
    db.commit()
    return RedirectResponse("/incidents?toast=Incident+created", status_code=303)


@router.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_detail_page(
    request: Request,
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    chain = get_accountability_chain(db, incident_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
    return templates.TemplateResponse(
        request,
        "incident_detail.html",
        _ctx(
            request,
            db,
            incident=incident,
            chain=chain,
        ),
    )


@router.post("/incidents/{incident_id}/resolve")
def resolve_incident_form(
    request: Request,
    incident_id: int,
    resolution_notes: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    verify_csrf(request, csrf_token)
    if user.role not in ("admin", "reviewer"):
        return RedirectResponse(f"/incidents/{incident_id}?toast=Auditors+cannot+resolve+incidents", status_code=303)

    if len(resolution_notes.strip()) < 10:
        return RedirectResponse(f"/incidents/{incident_id}?toast=Resolution+notes+must+be+at+least+10+characters", status_code=303)

    try:
        resolve_incident(db, incident_id, user, resolution_notes)
        db.commit()
    except (IncidentError, ValueError) as e:
        return RedirectResponse(f"/incidents/{incident_id}?toast={str(e)}", status_code=303)

    return RedirectResponse(f"/incidents/{incident_id}?toast=Incident+resolved", status_code=303)


>>>>>>> a981b25 (New Updates)
@router.get("/audit", response_class=HTMLResponse)
@router.get("/audit/agent/{agent_id}", response_class=HTMLResponse)
def audit_report(
    request: Request,
    agent_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    """Printable audit report for auditors (and Print → PDF)."""
    agent = None
    owner_name = None
    q = select(ActionRequest).order_by(ActionRequest.created_at.desc()).limit(200)
    if agent_id is not None:
        agent = db.execute(select(Agent).where(Agent.id == agent_id)).scalar_one_or_none()
        if agent is None:
            return templates.TemplateResponse(request, "404.html", _ctx(request, db), status_code=404)
        owner = db.execute(select(User).where(User.id == agent.owner_user_id)).scalar_one_or_none()
        owner_name = owner.name if owner else "?"
        q = (
            select(ActionRequest)
            .where(ActionRequest.agent_id == agent_id)
            .order_by(ActionRequest.created_at.desc())
            .limit(200)
        )
    actions = list(db.execute(q).scalars().all())
<<<<<<< HEAD
    users = {u.id: u for u in db.execute(select(User)).scalars().all()}
    rows = []
    for ar in actions:
        approver = None
        if ar.decided_by:
            u = users.get(ar.decided_by)
            approver = u.name if u else str(ar.decided_by)
        rows.append(
            {
                "ts": ar.created_at.strftime("%Y-%m-%d %H:%M") if ar.created_at else "",
                "tool": ar.tool,
                "decision": ar.decision or ar.status,
                "rule": ar.matched_rule_id,
                "approver": approver,
                "reason": (ar.decision_reason or ar.reason or "")[:120],
            }
        )
=======
    all_agents = list(db.execute(select(Agent)).scalars().all())
    agents_map = {a.id: a for a in all_agents}
    users = {u.id: u for u in db.execute(select(User)).scalars().all()}

    # Agents snapshot
    agents_snapshot = []
    target_agents = [agent] if agent else all_agents
    for ag in target_agents:
        ou = users.get(ag.owner_user_id)
        agents_snapshot.append({
            "id": ag.id,
            "name": ag.name,
            "purpose": ag.purpose,
            "owner_name": ou.name if ou else "Unknown",
            "owner_email": ou.email if ou else "",
            "risk_category": ag.risk_category,
            "permitted_actions": ag.permitted_actions or [],
            "data_access": ag.data_access or [],
            "status": ag.status,
            "status_reason": ag.status_reason,
        })

    # Approvals log
    approvals_log = []
    approvals = list(
        db.execute(
            select(ActionRequest)
            .where(ActionRequest.status.in_(["approved", "rejected"]))
            .order_by(ActionRequest.decided_at.desc())
            .limit(100)
        ).scalars().all()
    )
    for ar in approvals:
        if agent_id and ar.agent_id != agent_id:
            continue
        ag = agents_map.get(ar.agent_id)
        ou = users.get(ag.owner_user_id) if ag else None
        approver = users.get(ar.decided_by) if ar.decided_by else None
        approvals_log.append({
            "action_id": ar.id,
            "tool": ar.tool,
            "agent_name": ag.name if ag else "?",
            "owner_name": ou.name if ou else "?",
            "approver_name": approver.name if approver else "Auto",
            "decided_at": ar.decided_at.strftime("%Y-%m-%d %H:%M UTC") if ar.decided_at else "",
            "reason": ar.decision_reason or "",
        })

    # Breaches log
    breaches_log = []
    breach_actions = list(
        db.execute(
            select(ActionRequest)
            .where(ActionRequest.is_breach == True)  # noqa: E712
            .order_by(ActionRequest.created_at.desc())
            .limit(50)
        ).scalars().all()
    )
    for ba in breach_actions:
        if agent_id and ba.agent_id != agent_id:
            continue
        ag = agents_map.get(ba.agent_id)
        breaches_log.append({
            "ts": ba.created_at.strftime("%Y-%m-%d %H:%M UTC") if ba.created_at else "",
            "agent_name": ag.name if ag else "?",
            "tool": ba.tool,
            "reason": ba.breach_reason or "Policy breach detected",
            "action_taken": "Agent Paused, Incident Opened, Denied",
        })

    # Incidents log
    incidents_q = select(Incident).order_by(Incident.created_at.desc()).limit(50)
    if agent_id:
        incidents_q = incidents_q.where(Incident.agent_id == agent_id)
    incidents_rows = list(db.execute(incidents_q).scalars().all())
    incidents_log = []
    for inc in incidents_rows:
        ag = agents_map.get(inc.agent_id) if inc.agent_id else None
        ou = users.get(ag.owner_user_id) if ag else None
        incidents_log.append({
            "id": inc.id,
            "severity": inc.severity,
            "title": inc.title,
            "description": inc.description,
            "agent_name": ag.name if ag else "System-wide",
            "owner_name": ou.name if ou else "N/A",
            "status": inc.status,
            "resolution_notes": inc.resolution_notes,
        })

>>>>>>> a981b25 (New Updates)
    stats = {
        "total": len(actions),
        "allowed": sum(1 for a in actions if a.status in ("allowed", "approved", "completed")),
        "denied": sum(1 for a in actions if a.status in ("denied", "rejected")),
<<<<<<< HEAD
        "pending": sum(1 for a in actions if a.status in ("pending", "escalated")),
    }
    verify = ledger.verify(db)
    head = ledger.get_head(db)
=======
        "approved": len(approvals_log),
        "breaches": len(breaches_log),
        "open_incidents": sum(1 for i in incidents_rows if i.status in ("open", "investigating")),
        "total_incidents": len(incidents_rows),
    }
    verify = ledger.verify(db)
    head = ledger.get_head(db)

    checkpoint = None
    checkpoint_status = "VALID"
    try:
        from app.services.checkpoints import get_latest_checkpoint
        checkpoint = get_latest_checkpoint(db)
    except Exception:
        pass

>>>>>>> a981b25 (New Updates)
    return templates.TemplateResponse(
        request,
        "audit_report.html",
        _ctx(
            request,
            db,
            agent=agent,
            owner_name=owner_name,
<<<<<<< HEAD
            rows=rows,
            stats=stats,
            verify=verify,
            head=head,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        ),
    )

=======
            agents_snapshot=agents_snapshot,
            approvals_log=approvals_log,
            breaches_log=breaches_log,
            incidents_log=incidents_log,
            stats=stats,
            verify=verify,
            head=head,
            checkpoint=checkpoint,
            checkpoint_status=checkpoint_status,
            generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        ),
    )


@router.get("/audit/export")
def audit_export_json(
    request: Request,
    agent_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    """JSON export of governance audit report."""
    all_agents = list(db.execute(select(Agent)).scalars().all())
    agents_map = {a.id: a for a in all_agents}
    users = {u.id: u for u in db.execute(select(User)).scalars().all()}

    target_agents = [agents_map[agent_id]] if agent_id and agent_id in agents_map else all_agents

    agents_data = []
    for ag in target_agents:
        ou = users.get(ag.owner_user_id)
        agents_data.append({
            "id": ag.id,
            "name": ag.name,
            "purpose": ag.purpose,
            "owner": {"id": ou.id if ou else None, "name": ou.name if ou else None, "email": ou.email if ou else None},
            "risk_category": ag.risk_category,
            "status": ag.status,
            "status_reason": ag.status_reason,
            "permitted_actions": ag.permitted_actions or [],
            "data_access": ag.data_access or [],
            "breach_count": ag.breach_count,
            "cost_per_call": ag.cost_per_call,
        })

    q = select(ActionRequest).order_by(ActionRequest.created_at.desc()).limit(200)
    if agent_id:
        q = q.where(ActionRequest.agent_id == agent_id)
    actions = list(db.execute(q).scalars().all())

    actions_data = []
    for ar in actions:
        ag = agents_map.get(ar.agent_id)
        decider = users.get(ar.decided_by) if ar.decided_by else None
        actions_data.append({
            "id": ar.id,
            "agent_id": ar.agent_id,
            "agent_name": ag.name if ag else None,
            "tool": ar.tool,
            "params": redact_params(ar.params or {}, getattr(ar, "sensitivity", "internal")),
            "data_used": getattr(ar, "data_used", None) or [],
            "decision": ar.decision,
            "matched_rule_id": ar.matched_rule_id,
            "status": ar.status,
            "is_breach": getattr(ar, "is_breach", False),
            "breach_reason": getattr(ar, "breach_reason", None),
            "decided_by": decider.name if decider else None,
            "decision_reason": ar.decision_reason,
            "created_at": ar.created_at.isoformat() if ar.created_at else None,
        })

    inc_q = select(Incident).order_by(Incident.created_at.desc()).limit(50)
    if agent_id:
        inc_q = inc_q.where(Incident.agent_id == agent_id)
    incidents = list(db.execute(inc_q).scalars().all())
    incidents_data = [
        {
            "id": inc.id,
            "title": inc.title,
            "description": inc.description,
            "severity": inc.severity,
            "status": inc.status,
            "agent_id": inc.agent_id,
            "resolution_notes": inc.resolution_notes,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
        }
        for inc in incidents
    ]

    verify = ledger.verify(db)
    head = ledger.get_head(db)

    report = {
        "report_type": "AgentWarden Governance Audit Report",
        "generated_at": datetime.now(UTC).isoformat(),
        "ledger_verification": verify,
        "ledger_head": head,
        "agents": agents_data,
        "recent_actions": actions_data,
        "incidents": incidents_data,
    }
    return JSONResponse(report)


>>>>>>> a981b25 (New Updates)
