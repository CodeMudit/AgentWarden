# AgentWarden

**AI Agent Governance and Human Accountability System**

AI agents are being given real authority (refunds, emails, data access), but nobody can reliably say: was this action allowed, under which rule, which human is responsible, and can the record be trusted?

AgentWarden is a governance layer that sits between AI agents and the tools they use. Before an agent performs a risky action it asks AgentWarden. A deterministic, default-deny policy engine answers **ALLOW**, **DENY**, or **REQUIRE_APPROVAL**. Risky requests wait in a human reviewer queue. Every event is written to an append-only, hash-chained ledger that anyone can re-verify, and every agent has a named human owner. Approvers must give a written reason, and nobody can approve their own agent's actions.

> Built for CodeX 3.0 (problem statement: AI Agent Governance and Human Accountability System).

**Screenshots:** *(placeholders until Phase 2 UI is complete)*

---

## Quickstart

```bash
# Clone / enter repo
cd agentwarden

# Install (Python 3.12+)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .

# Copy env and run
cp .env.example .env
make run          # or: uvicorn app.main:app --reload --port 8000

# In another terminal
curl http://localhost:8000/health
# {"status":"ok","app":"AgentWarden","version":"0.1.0","db":"ok","ledger_head_seq":null}
```

```bash
make test   # pytest
make lint   # ruff
```

---

## Architecture

```mermaid
flowchart LR
  Agent[AI Agent / SDK] -->|X-API-Key| API[FastAPI /v1]
  API --> Policy[Policy Engine<br/>default-deny]
  API --> Ledger[Hash-chained Ledger]
  API --> Queue[Approval Queue]
  Reviewer[Human Reviewer] --> Web[Jinja2 + HTMX UI]
  Web --> API
  Admin[Admin] --> Web
  Ledger --> Verify[Verify / Checkpoint]
```

- **Policy engine** is pure and deterministic (no DB, no I/O). Lowest priority matching rule wins; unmatched → DENY.
- **Ledger** is append-only with SHA-256 hash chaining and concurrent-safe head locking.
- **Separation of duties**: agent owners cannot approve their own agents' requests.
- No LLM ever makes or changes a decision. Optional Anthropic key only rewords plain-language summaries.

---

## Handoff: Read This First

### Project summary for a fresh LLM

AgentWarden is a FastAPI governance layer for AI agents: policy engine (ALLOW/DENY/REQUIRE_APPROVAL), human approval queue, append-only hash-chained ledger, named human owners per agent. Stack: Python 3.12, FastAPI, SQLAlchemy 2, Alembic, Jinja2+HTMX+Tailwind (CDN), SQLite default / Postgres via DATABASE_URL. Non-negotiable: no LLM decisions, default-deny, no fake data in app code, no placeholders/TODOs, tests must pass, scope is the feature list only. Run from repo root with PYTHONPATH=. or after `pip install -e .`.

### Current status

- Current phase: **2**
- Last updated: 2026-10-10 ~22:00 IST
- Overall: Core engine + full human UI. Session auth, CSRF, design system, pages: Login, Overview, Live Feed, Approvals, Agents, Agent detail, Policies, Ledger, 404/500. API from Phase 1 still works. Demo Lab / seed arrive in Phase 3.
- Tests: **37 passed** (`PYTHONPATH=. python3 -m pytest -v`)
- `make verify`: not yet implemented (Phase 3)

### Feature checklist

| Feature | Status | Where in code | How to check it |
|---------|--------|---------------|-----------------|
| Repo structure / config / Makefile | done and tested | `app/config.py`, `Makefile`, `pyproject.toml` | `make help`; `curl /health` |
| DB engine + Alembic | done and tested | `app/db.py`, `alembic/` | tables created on startup; migration exists |
| `/health` | done and tested | `app/main.py` | `GET /health` → 200 + db ok |
| Policy engine | done and tested | `app/policy/engine.py` | pytest tests/test_policy_engine.py |
| Ledger | done and tested | `app/ledger.py` | pytest tests/test_ledger.py |
| Agent auth + actions API | done and tested | `app/api/actions.py`, `app/security.py` | curl /v1/actions/request |
| Approvals + separation of duties | done and tested | `app/services/approvals.py` | pytest workflow tests |
| Escalation task | done and tested | `app/services/escalation.py` | test_escalation |
| Simulator | done and tested | `app/policy/simulator.py` | test_policy_simulate |
| Human auth / CSRF / RBAC | done and tested | `app/security.py`, `app/web/routes.py` | login + CSRF tests |
| UI pages | done and tested | `app/web/templates/`, `app/web/routes.py` | browser login → overview |
| Seed / Demo Lab / SDK / smoke | not started | `scripts/`, `sdk/` | — |
| Docker + Postgres | skeleton only | `Dockerfile`, `docker-compose.yml` | not fully exercised yet |

### How to run, test, and demo

```bash
# Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && pip install -e .
cp .env.example .env

# Run
make run                    # uvicorn on :8000
# or: PYTHONPATH=. uvicorn app.main:app --reload --port 8000

# Test / lint
PYTHONPATH=. python3 -m pytest -v
PYTHONPATH=. ruff check --no-cache app tests scripts sdk
PYTHONPATH=. ruff format --check --no-cache app tests scripts sdk

# Seed / demo / verify → Phase 3
# Docker → make docker-up (app + Postgres)
```

### Decisions and Assumptions

1. Phase 0 uses a minimal `HealthCheck` model so `create_all` / Alembic have a real table; full domain models arrive in Phase 1.
2. Alembic is preferred over bare `create_all`; startup still calls `init_db()` for convenience in dev/tests.
3. SQLite is the default; `DATABASE_URL` switches to Postgres without code changes.
4. Makefile targets `seed`/`demo`/`verify` intentionally exit 1 until Phase 3 implements them.
5. Packages installed system/user-wide in this environment when venv creation failed; production path uses `.venv` as documented.

### Known issues and limitations

- No domain models, policy, ledger, auth, or UI yet (by design for Phase 0).
- `make setup` expects a working venv; some sandboxed environments need `PYTHONPATH=.` and user-site packages.
- Ledger head seq is `null` until Phase 1.
- Docker Compose not yet smoke-tested end-to-end.

### Next steps (ordered)

1. **Phase 3 – Demo**: seed script, Demo Lab, demo_agent.py, SDK, smoke_test / make verify.
2. Acceptance: make verify passes from clean seed.
3. Phase 4 – Polish: Docker Postgres verification, DEMO_SCRIPT.md, final README.

### Conventions

- Code style: ruff (line length 100, py312). Prefer explicit types.
- Naming: snake_case modules/functions, PascalCase models/schemas.
- New policy condition type: add to `app/policy/engine.py` evaluator + validation on policy save + unit tests.
- New ledger event type: add to allowed set in `app/ledger.py` + emit from the relevant service + test.
- New page (Phase 2+): router in `app/web/`, template under `app/web/templates/`, link in sidebar.

### Session log (append-only, newest last)

#### Session 1: 2026-10-10

- Goal: Complete Phase 0 (skeleton).
- What I changed (files and a one-line why for each):
  - `pyproject.toml`, `requirements.txt` – project metadata and dependencies
  - `.env.example`, `.gitignore`, `LICENSE` – env docs, ignore rules, MIT
  - `app/config.py`, `app/db.py`, `app/main.py`, `app/models.py` – settings, engine/session, FastAPI app + `/health`, minimal HealthCheck model
  - `app/schemas.py`, `app/security.py`, `app/policy/*`, `app/ledger.py`, `app/services/`, `app/api/`, `app/web/` – package placeholders
  - `alembic/` + initial migration – migrations preferred
  - `Makefile`, `Dockerfile`, `docker-compose.yml`, `.github/workflows/ci.yml` – build/run/CI
  - `tests/test_health.py`, `tests/conftest.py` – Phase 0 tests
  - `sdk/`, `scripts/` – placeholders for Phase 3
  - `README.md` – public docs + Handoff system
- What I ran and the real results:
  - `pip install` of requirements → success
  - `PYTHONPATH=. python3 -m pytest -v` → **2 passed**
  - `ruff check/format --no-cache` → all checks passed after format fix
  - `/health` via TestClient → `200 {"status":"ok","app":"AgentWarden","version":"0.1.0","db":"ok","ledger_head_seq":null}`
  - `alembic revision --autogenerate` → created `phase0_health_check` migration
- Decisions made: minimal HealthCheck model for Phase 0; Alembic + create_all on startup; Makefile stubs exit 1 for seed/demo/verify.
- Problems found and whether they are fixed:
  - venv creation failed in sandbox (permission on lib64) → used user-site install + PYTHONPATH; documented in Decisions.
  - ruff cache write failure → used `--no-cache`.
- Left unfinished: full domain models, policy, ledger, auth, UI, demo (all later phases).
- Next step for whoever continues: **Phase 1 – Core engine** (done in Session 2).

---

## API examples

```bash
# Health (no auth)
curl -s http://localhost:8000/health | jq

# Bootstrap admin (first user needs no auth)
curl -s -X POST http://localhost:8000/v1/users \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","name":"Admin","password":"password123","role":"admin"}' | jq

# Create reviewer, then agent (X-User-Id = admin id)
curl -s -X POST http://localhost:8000/v1/users -H 'Content-Type: application/json' \
  -H 'X-User-Id: 1' \
  -d '{"email":"rev@example.com","name":"Rev","password":"password123","role":"reviewer"}' | jq

curl -s -X POST http://localhost:8000/v1/agents -H 'Content-Type: application/json' \
  -H 'X-User-Id: 1' \
  -d '{"name":"refund-bot","purpose":"refunds","owner_user_id":2,"risk_tier":"medium"}' | jq
# Save api_key from response

# Create + activate policy
curl -s -X POST http://localhost:8000/v1/policies -H 'Content-Type: application/json' \
  -H 'X-User-Id: 1' \
  -d '{"rules":{"default_effect":"deny","rules":[{"id":"small","priority":10,"match":{"agents":["refund-bot"],"tools":["issue_refund"]},"conditions":[{"type":"amount_lte","field":"amount","value":100}],"effect":"allow"}]},"note":"v1"}' | jq

curl -s -X POST http://localhost:8000/v1/policies/1/activate -H 'X-User-Id: 1' | jq

# Agent requests action
curl -s -X POST http://localhost:8000/v1/actions/request \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  -d '{"tool":"issue_refund","params":{"amount":40},"sensitivity":"internal"}' | jq

# Large refund → require_approval, then approve as non-owner
curl -s -X POST http://localhost:8000/v1/actions/request \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  -d '{"tool":"issue_refund","params":{"amount":900},"sensitivity":"internal"}' | jq

curl -s -X POST http://localhost:8000/v1/approvals/2/approve \
  -H 'X-User-Id: 1' -H 'Content-Type: application/json' \
  -d '{"reason":"Reviewed and looks legitimate for this customer"}' | jq

# Ledger verify
curl -s -X POST http://localhost:8000/v1/ledger/verify -H 'X-User-Id: 1' | jq
```

---

## Security notes and limitations

*(Expanded in Phase 4. Current Phase 0 notes:)*

- No authentication yet (Phase 1/2).
- Secrets must come from environment variables; never hard-code.
- The ledger will be **tamper-evident**, not tamper-proof. Agent self-declared sensitivity is a known limitation (honest disclosure required in final README).

---

## Credits and licenses

- MIT License (see `LICENSE`).
- Stack: FastAPI, SQLAlchemy, Alembic, Pydantic, argon2-cffi, Jinja2, HTMX, Tailwind CSS (CDN), Alpine.js (CDN), Chart.js (CDN), rich.
- No third-party application code reused yet.

#### Session 2: 2026-10-10

- Goal: Complete Phase 1 (core engine).
- What I changed:
  - `app/models.py` – full domain models (User, Agent, Policy, ActionRequest, LedgerEntry, LedgerHead, SystemState)
  - `app/policy/engine.py` – pure evaluator with all condition types + validate_policy
  - `app/policy/simulator.py` – replay draft policy against history
  - `app/ledger.py` – append/verify/checkpoint/HMAC, concurrent-safe head lock
  - `app/security.py` – argon2 passwords, API key hash, agent/user auth deps
  - `app/schemas.py` – Pydantic request/response models
  - `app/services/{actions,approvals,escalation,summaries,killswitch}.py` – workflow services
  - `app/api/{actions,approvals,agents,policies,ledger_api,system,users}.py` – JSON API under /v1
  - `app/main.py` – routers, genesis, escalation background task
  - `tests/test_policy_engine.py`, `test_ledger.py`, `test_workflow.py` – coverage
  - Alembic migration `phase1_domain_models`
- What I ran: `PYTHONPATH=. python3 -m pytest tests/ -v` → **33 passed**; ruff check → all passed
- Decisions: Phase 1 human auth via X-User-Id header (sessions in Phase 2); SQLite concurrent test serializes writers with a lock (real FOR UPDATE on Postgres); rate_limit condition is TRUE when count >= max
- Problems fixed: nested BEGIN IMMEDIATE on SQLite; Pydantic from_attributes; FastAPI detail wrapper in tests
- Left unfinished: UI (Phase 2), seed/demo/SDK (Phase 3)
- Next step: Phase 2 – Human interface (auth sessions, CSRF, all pages)

#### Session 3: 2026-10-10

- Goal: Complete Phase 2 (human interface).
- What I changed:
  - `app/security.py` – session cookies, CSRF, RedirectToLogin, require_web_user
  - `app/web/routes.py` – all HTML routes (login, overview, feed, approvals, agents, policies, ledger, partials)
  - `app/web/templates/*` – base layout + design system (Tailwind/Alpine/HTMX/Chart.js), all pages
  - `app/main.py` – mount web router, security headers, 404/500, RedirectToLogin handler
  - `scripts/bootstrap_admin.py` – create demo users for UI testing
  - `tests/test_web_auth.py` – login, overview, redirect, CSRF smoke
- What I ran: pytest → **37 passed**; ruff → all checks passed
- Decisions: Starlette 1.7 TemplateResponse(request, name, context); Phase 1 X-User-Id API auth kept alongside sessions; auditors are read-only in approval UI
- Left unfinished: Demo Lab, seed historical data, SDK, smoke verify (Phase 3)
- Next step: Phase 3 – Demo

