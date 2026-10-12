"""Decision token verification endpoints for tool backends."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.schemas import TokenVerifyIn, TokenVerifyOut
from app.tokens import get_public_key_jwk, verify_and_consume

router = APIRouter(tags=["tokens"])


@router.get("/.well-known/keys")
def well_known_keys():
    """Public key for offline token verification."""
    return {"keys": [get_public_key_jwk()]}


@router.post("/tokens/verify", response_model=TokenVerifyOut)
def verify_token(body: TokenVerifyIn, db: Session = Depends(get_db)):
    """Verify and consume a decision token (tool backends).

    On success the token is marked consumed (replay will fail).
    Optional expected_tool / params_hash / agent_id bindings are checked.
    """
    result = verify_and_consume(
        db,
        body.token,
        expected_tool=body.tool,
        expected_params_hash=body.params_hash,
        expected_agent_id=body.agent_id,
    )
    db.commit()
    return TokenVerifyOut(valid=result.valid, reason=result.reason, claims=result.claims)
