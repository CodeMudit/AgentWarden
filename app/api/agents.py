"""Agent CRUD and suspend/resume."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger
from app.db import get_db
from app.models import Agent, User
from app.schemas import AgentCreateIn, AgentCreateOut, AgentOut
from app.security import generate_api_key, require_admin, require_reviewer_or_admin
from app.services.killswitch import resume_agent, suspend_agent

router = APIRouter(prefix="/agents", tags=["agents"])


@router.get("", response_model=list[AgentOut])
def list_agents(
    user: User = Depends(require_reviewer_or_admin),
    db: Session = Depends(get_db),
):
    rows = list(db.execute(select(Agent).order_by(Agent.id)).scalars().all())
    return [AgentOut.model_validate(a) for a in rows]


@router.post("", response_model=AgentCreateOut, status_code=201)
def create_agent(
    body: AgentCreateIn,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    existing = db.execute(select(Agent).where(Agent.name == body.name)).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": {"code": "conflict", "message": "Agent name already exists"}},
        )
    owner = db.execute(select(User).where(User.id == body.owner_user_id)).scalar_one_or_none()
    if owner is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "invalid_owner", "message": "Owner user not found"}},
        )
    full_key, prefix, key_hash = generate_api_key()
    agent = Agent(
        name=body.name,
        purpose=body.purpose,
        owner_user_id=body.owner_user_id,
        risk_tier=body.risk_tier,
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
        payload={"name": agent.name, "owner_user_id": agent.owner_user_id},
    )
    db.commit()
    db.refresh(agent)
    return AgentCreateOut(
        id=agent.id,
        name=agent.name,
        purpose=agent.purpose,
        owner_user_id=agent.owner_user_id,
        risk_tier=agent.risk_tier,
        status=agent.status,
        api_key_prefix=agent.api_key_prefix,
        created_at=agent.created_at,
        api_key=full_key,
    )


@router.post("/{agent_id}/suspend", response_model=AgentOut)
def suspend(
    agent_id: int,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    agent = db.execute(select(Agent).where(Agent.id == agent_id)).scalar_one_or_none()
    if agent is None:
        raise HTTPException(
            status_code=404, detail={"error": {"code": "not_found", "message": "Agent not found"}}
        )
    suspend_agent(db, agent, by=str(user.id))
    db.commit()
    db.refresh(agent)
    return AgentOut.model_validate(agent)


@router.post("/{agent_id}/resume", response_model=AgentOut)
def resume(
    agent_id: int,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    agent = db.execute(select(Agent).where(Agent.id == agent_id)).scalar_one_or_none()
    if agent is None:
        raise HTTPException(
            status_code=404, detail={"error": {"code": "not_found", "message": "Agent not found"}}
        )
    resume_agent(db, agent, by=str(user.id))
    db.commit()
    db.refresh(agent)
    return AgentOut.model_validate(agent)
