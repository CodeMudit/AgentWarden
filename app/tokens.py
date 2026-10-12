"""Ed25519-signed, short-lived, single-use decision tokens.

Tokens bind: action_id, agent_id, tool, params_hash, policy_version, expiry, nonce.
Issued only after ALLOW or human-approved REQUIRE_APPROVAL.
Tool backends call verify (online or offline with public key) and refuse without a valid token.

Does NOT protect against: tool backends that never verify tokens.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import ledger
from app.config import get_settings
from app.models import DecisionToken

# Default lifetime
DEFAULT_TTL_SECONDS = 300  # 5 minutes


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def canonical_token_payload(claims: dict[str, Any]) -> bytes:
    """Stable bytes for signing (sorted keys, no whitespace)."""
    return json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

_private_key: Ed25519PrivateKey | None = None
_public_key: Ed25519PublicKey | None = None
_key_id: str = "default"


def _load_or_generate_keys() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    global _private_key, _public_key, _key_id
    if _private_key is not None and _public_key is not None:
        return _private_key, _public_key, _key_id

    settings = get_settings()
    # Prefer env seed or file; fall back to deterministic-from-secret for demos
    seed_hex = os.environ.get("TOKEN_SIGNING_SEED")
    key_path = os.environ.get("TOKEN_SIGNING_KEY_PATH")

    if key_path and Path(key_path).exists():
        raw = Path(key_path).read_bytes()
        private = serialization.load_pem_private_key(raw, password=None)
        assert isinstance(private, Ed25519PrivateKey)
    elif seed_hex:
        seed = bytes.fromhex(seed_hex)
        if len(seed) != 32:
            seed = hashlib.sha256(seed).digest()
        private = Ed25519PrivateKey.from_private_bytes(seed)
    else:
        # Derive stable demo key from SECRET_KEY so restarts keep the same key
        material = hashlib.sha256(
            (settings.secret_key + "|token-signing-v1").encode("utf-8")
        ).digest()
        private = Ed25519PrivateKey.from_private_bytes(material)

    public = private.public_key()
    pub_bytes = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    kid = hashlib.sha256(pub_bytes).hexdigest()[:16]

    _private_key = private
    _public_key = public
    _key_id = kid
    return private, public, kid


def get_public_key_jwk() -> dict[str, str]:
    """Return public key in a simple JWK-like dict for /.well-known/keys."""
    _, public, kid = _load_or_generate_keys()
    pub_bytes = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(pub_bytes),
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
    }


def get_public_key_raw() -> bytes:
    _, public, _ = _load_or_generate_keys()
    return public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


# ---------------------------------------------------------------------------
# Issue / verify
# ---------------------------------------------------------------------------


@dataclass
class TokenClaims:
    action_id: int
    agent_id: int
    tool: str
    params_hash: str
    policy_version: int | None
    exp: int  # unix timestamp
    nonce: str
    kid: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "params_hash": self.params_hash,
            "policy_version": self.policy_version,
            "exp": self.exp,
            "nonce": self.nonce,
            "kid": self.kid,
        }


def issue_token(
    db: Session,
    *,
    action_id: int,
    agent_id: int,
    tool: str,
    params_hash: str,
    policy_version: int | None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> str:
    """Create a signed token and persist a DecisionToken row (unconsumed)."""
    private, _, kid = _load_or_generate_keys()
    now = int(time.time())
    claims = TokenClaims(
        action_id=action_id,
        agent_id=agent_id,
        tool=tool,
        params_hash=params_hash,
        policy_version=policy_version,
        exp=now + ttl_seconds,
        nonce=secrets.token_hex(16),
        kid=kid,
    )
    payload_bytes = canonical_token_payload(claims.to_dict())
    sig = private.sign(payload_bytes)
    token = _b64url(payload_bytes) + "." + _b64url(sig)

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = DecisionToken(
        token_hash=token_hash,
        action_id=action_id,
        agent_id=agent_id,
        tool=tool,
        params_hash=params_hash,
        policy_version=policy_version,
        nonce=claims.nonce,
        expires_at=datetime.fromtimestamp(claims.exp, tz=UTC),
        consumed_at=None,
    )
    db.add(row)
    db.flush()

    ledger.append(
        db,
        event_type="token_issued",
        actor_type="system",
        actor_id="token_service",
        subject_type="action_request",
        subject_id=str(action_id),
        payload={
            "token_hash": token_hash,
            "tool": tool,
            "params_hash": params_hash,
            "exp": claims.exp,
            "nonce": claims.nonce,
        },
        policy_version=policy_version,
    )
    db.flush()
    return token


@dataclass
class VerifyResult:
    valid: bool
    reason: str
    claims: dict[str, Any] | None = None


def verify_token_offline(token: str, public_key_raw: bytes | None = None) -> VerifyResult:
    """Verify signature + expiry without DB. Does not check single-use."""
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return VerifyResult(False, "malformed token")
        payload_bytes = _b64url_decode(parts[0])
        sig = _b64url_decode(parts[1])
        claims = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return VerifyResult(False, "malformed token")

    if public_key_raw is None:
        public_key_raw = get_public_key_raw()
    public = Ed25519PublicKey.from_public_bytes(public_key_raw)
    try:
        public.verify(sig, payload_bytes)
    except InvalidSignature:
        return VerifyResult(False, "invalid signature")

    now = int(time.time())
    if int(claims.get("exp", 0)) < now:
        return VerifyResult(False, "token expired")

    return VerifyResult(True, "ok", claims)


def verify_and_consume(
    db: Session,
    token: str,
    *,
    expected_tool: str | None = None,
    expected_params_hash: str | None = None,
    expected_agent_id: int | None = None,
) -> VerifyResult:
    """Full online verify: signature, expiry, bindings, single-use consume."""
    offline = verify_token_offline(token)
    if not offline.valid:
        ledger.append(
            db,
            event_type="token_invalid",
            actor_type="system",
            actor_id="token_service",
            subject_type="token",
            subject_id=None,
            payload={"reason": offline.reason},
        )
        db.flush()
        return offline

    claims = offline.claims or {}
    if expected_tool is not None and claims.get("tool") != expected_tool:
        return _reject(db, claims, "tool mismatch")
    if expected_params_hash is not None and claims.get("params_hash") != expected_params_hash:
        return _reject(db, claims, "params_hash mismatch")
    if expected_agent_id is not None and int(claims.get("agent_id", -1)) != expected_agent_id:
        return _reject(db, claims, "agent_id mismatch")

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = db.execute(
        select(DecisionToken).where(DecisionToken.token_hash == token_hash)
    ).scalar_one_or_none()
    if row is None:
        return _reject(db, claims, "token not found (revoked or never issued)")
    if row.consumed_at is not None:
        ledger.append(
            db,
            event_type="token_replay_blocked",
            actor_type="system",
            actor_id="token_service",
            subject_type="action_request",
            subject_id=str(row.action_id),
            payload={"token_hash": token_hash, "nonce": row.nonce},
            policy_version=row.policy_version,
        )
        db.flush()
        return VerifyResult(False, "token already consumed (replay)")

    # Check agent not suspended via action binding is enough for now
    row.consumed_at = datetime.now(UTC)
    db.flush()
    ledger.append(
        db,
        event_type="token_consumed",
        actor_type="system",
        actor_id="token_service",
        subject_type="action_request",
        subject_id=str(row.action_id),
        payload={"token_hash": token_hash, "tool": row.tool},
        policy_version=row.policy_version,
    )
    db.flush()
    return VerifyResult(True, "ok", claims)


def _reject(db: Session, claims: dict, reason: str) -> VerifyResult:
    ledger.append(
        db,
        event_type="token_invalid",
        actor_type="system",
        actor_id="token_service",
        subject_type="action_request",
        subject_id=str(claims.get("action_id")),
        payload={"reason": reason, "claims": claims},
        policy_version=claims.get("policy_version"),
    )
    db.flush()
    return VerifyResult(False, reason)
