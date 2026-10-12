# AgentWarden Threat Model

**Scope:** Local / single-tenant deployment used as a governance layer between AI agents and tools.  
**Goal:** Make allow/deny/approve decisions deterministic, accountable to named humans, and tamper-evident.

---

## 1. Assets

| Asset | Why it matters |
|-------|----------------|
| Policy rules | Define what agents may do; compromised rules = unauthorized actions |
| Approval decisions | Human accountability; forged approvals break SoD |
| Decision tokens | Capability to invoke tools; stolen/replayed tokens = unauthorized tool use |
| Ledger entries | Audit trail; rewritten history hides misbehavior |
| Agent API keys | Agent identity; stolen key = impersonation |
| Human session cookies | Reviewer/admin identity |
| Tool registry secrets | Gateway auth to backends |
| Checkpoint signing keys | Integrity of exported evidence |

---

## 2. Actors

| Actor | Capabilities | Motivation |
|-------|--------------|------------|
| Honest agent | Calls AgentWarden with valid API key | Perform assigned tasks |
| Compromised / malicious agent | Has API key; may try to skip governance, alter params, replay | Exfiltrate, fraud, evade policy |
| Tool backend | Receives tool invocations | May or may not verify tokens |
| Reviewer / admin | Session auth; approve/reject; manage policy | Collusion, self-approval, policy sabotage |
| External attacker | Network access; no credentials | Steal keys, forge requests, rewrite DB |
| Insider with DB access | Can modify SQLite/Postgres | Rewrite ledger, alter approvals |

---

## 3. Attacks and mitigations

### 3.1 Agent bypass (call tools without AgentWarden)

**Attack:** Agent ignores AgentWarden and calls the tool HTTP endpoint directly.

**Mitigation:**
- Decision tokens (Ed25519, short-lived, single-use) issued only after ALLOW or approved REQUIRE_APPROVAL.
- Tool backends must call `POST /v1/tokens/verify` (or use offline `agentwarden_verify` with public key from `GET /v1/.well-known/keys`) and refuse calls without a valid, unconsumed token.
- Gateway mode: `POST /v1/gateway/execute` is the only path that invokes registered tools after a decision.

**Does not protect against:** Tool backends that are not instrumented to verify tokens. Operators must deploy verification at the tool boundary.

---

### 3.2 Parameter tampering (TOCTOU)

**Attack:** Agent requests approval for `$900` refund, receives approval, then executes `$9000`.

**Mitigation:**
- `params_hash = sha256(canonical_json(params))` computed at request time and stored on the action and in ledger payloads.
- Approval UI shows exact params and hash.
- On complete / token use, reject if params differ (`param_mismatch_blocked` ledger event).

**Does not protect against:** Semantic equivalence attacks (e.g. `amount: 900` vs `amount: "900.00"`) if canonicalization is inconsistent—canonical JSON with sorted keys and fixed separators is required.

---

### 3.3 Approver collusion / self-approval

**Attack:** Agent owner approves their own agent’s high-value action; or two colluding reviewers rubber-stamp.

**Mitigation:**
- Separation of duties enforced in the service layer: `agent.owner_user_id != approver.id`.
- Written reason ≥ 10 characters required.
- Multi-approver quorum for amounts above a policy threshold (2-of-N, distinct humans, none the owner) where configured.
- Delegation / out-of-office with expiry; chain recorded in ledger; still no self-approval.

**Does not protect against:** Collusion among distinct non-owner reviewers who both intend to approve. Quorum and written reasons raise the bar; they do not eliminate social collusion.

---

### 3.4 Ledger rewrite

**Attack:** Attacker with DB access deletes or rewrites ledger rows / head to hide an event.

**Mitigation:**
- Append-only hash chain (SHA-256 over prev_hash + canonical payload).
- Ed25519-signed checkpoints (HMAC retained for back-compat).
- Merkle inclusion proofs (`GET /v1/ledger/proof/{seq}`).
- Evidence export + standalone offline verifier (`scripts/verify_bundle.py`) with zero app/DB dependency.
- Optional external anchoring of checkpoint hashes.

**Does not protect against:** Full DB rewrite *without* external checkpoints or anchors. The system is **tamper-evident**, not tamper-proof. Operators must store checkpoints / anchors outside the primary DB.

---

### 3.5 Replayed approvals / tokens

**Attack:** Capture a valid decision token or approval and reuse it for another call.

**Mitigation:**
- Tokens are single-use; marked consumed on verify; replay → reject + ledger event.
- Short default lifetime (5 minutes).
- Token binds action_id, agent_id, tool, params_hash, policy_version, expiry, nonce.

**Does not protect against:** Race conditions if two verifiers accept the same token before either marks it consumed (mitigated by transactional consume; residual risk under extreme concurrency without strong isolation).

---

### 3.6 Identity forgery

**Attack:** Forge `X-User-Id` or steal session cookie to act as another reviewer.

**Mitigation:**
- Human API and UI authenticate via signed session cookies only. `X-User-Id` is not accepted.
- CSRF tokens on state-changing web forms.
- Agent identity via hashed API keys (`X-API-Key`).
- Login rate limiting.

**Does not protect against:** Stolen session cookies (use HTTPS and short session lifetime in production) or stolen agent API keys (rotate keys; suspend compromised agents).

---

### 3.7 Policy sabotage

**Attack:** Admin activates a permissive policy that allows dangerous tools.

**Mitigation:**
- Policy activation requires a second admin (four-eyes) where configured; change logged in ledger.
- Policy simulator dry-runs proposed policy against recent real actions before activation.
- Default-deny remains: unmatched requests are denied.

**Does not protect against:** Two colluding admins, or a single admin in deployments that disable four-eyes.

---

## 4. Residual risk summary

| Risk | Residual? | Operator action |
|------|-----------|-----------------|
| Uninstrumented tool backends | Yes | Deploy token verification or use gateway mode |
| Full DB rewrite without anchors | Yes | Export checkpoints; optional external anchoring |
| Colluding non-owner reviewers | Yes | Quorum + audit review of reasons |
| Stolen API keys / sessions | Yes | HTTPS, key rotation, short sessions, suspend |
| Self-declared sensitivity | Yes | Future: server-side classification |
| Canonicalization edge cases | Low | Keep canonical_json stable; tests cover amount forms |

---

## 5. Trust boundaries

```
┌─────────────────────────────────────────────────────────┐
│  Untrusted: AI agent process, network, user devices     │
├─────────────────────────────────────────────────────────┤
│  AgentWarden API + policy engine + ledger               │
│  (trusted to evaluate rules and record events)          │
├─────────────────────────────────────────────────────────┤
│  Tool backends (must verify tokens to enforce)          │
├─────────────────────────────────────────────────────────┤
│  External checkpoint store / anchor (optional)          │
└─────────────────────────────────────────────────────────┘
```

AgentWarden cannot enforce governance on tools that never check tokens. The security claim is: **if tool backends verify tokens (or traffic goes through the gateway), then unauthorized tool use is refused and every governed decision is accountable and tamper-evident.**
