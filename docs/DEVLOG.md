# AgentWarden – Development Log / Handoff

Append-only session notes for maintainers and fresh LLM context.
Product-facing content lives in [README.md](../README.md).

---

## Project summary for a fresh LLM

AgentWarden is a FastAPI governance layer for AI agents: policy engine
(ALLOW/DENY/REQUIRE_APPROVAL), human approval queue, append-only
hash-chained ledger, named human owners.

**Stack:** Python 3.12, FastAPI, SQLAlchemy 2, Alembic, Jinja2+HTMX+Tailwind CDN.

**Non-negotiable:**
- No LLM ever makes or changes an allow/deny/approve decision.
- Default-deny. Rules decide. App works fully with no API key.
- No fake data in application code. No placeholders/TODO stubs.
- Every schema change = Alembic migration.
- Every new feature ships with pytest tests. Keep pytest green, ruff clean.
- Do not weaken session-only human auth, CSRF, or SoD in the service layer.
- Update `EVENT_TYPES` and tests when adding ledger events. Existing ledgers must still verify.

**Out of scope by design:** OAuth, Slack notifications, multi-tenancy, K8s.

---

## Status at handoff (2026-10-10)

- Phase: **4** (complete) + security hardening (session-only human API)
- Tests: **38 passed**
- `make verify`: PASS (server running + seeded)

### Feature checklist (baseline)

| Feature | Status | Where |
|---------|--------|-------|
| Policy engine | done | `app/policy/engine.py` |
| Ledger | done | `app/ledger.py` |
| Actions API | done | `app/api/actions.py` |
| Approvals + SoD | done | `app/services/approvals.py` |
| Escalation | done | `app/services/escalation.py` |
| Simulator | done | `app/policy/simulator.py` |
| Session auth + CSRF | done | `app/security.py` |
| UI pages | done | `app/web/` |
| Seed / Demo Lab / SDK | done | `scripts/`, `sdk/` |
| Smoke verify | done | `scripts/smoke_test.py` |
| Docker Compose | done | `Dockerfile`, `docker-compose.yml` |
| DEMO_SCRIPT | done | `docs/DEMO_SCRIPT.md` |

---

## Decisions and Assumptions

1. Phase 1 human API auth used `X-User-Id` header; Phase 2+ browser uses signed session cookies only. `X-User-Id` is removed (forgery vector).
2. `rate_limit` condition is TRUE when count ≥ max (so a deny rule fires when over limit).
3. SQLite concurrent-append tests serialize writers; Postgres uses `FOR UPDATE` on `LedgerHead`.
4. Starlette 1.7 `TemplateResponse(request, name, context)`.
5. Agent sensitivity is self-declared (documented limitation).
6. Ledger is tamper-**evident**, not tamper-proof; checkpoints + external HMAC address full-chain rewrite detection.
7. Optional LLM only rewords summaries; never decides.

---

## Known limitations (baseline)

- Sensitivity is declared by the agent, not classified server-side.
- Ledger integrity requires offline checkpoints to detect a full DB rewrite.
- Demo passwords are for local/hackathon use only.
- SQLite is fine for demo; use Postgres (`DATABASE_URL`) for concurrent load.
- Agents can still call tools directly if tool backends do not verify tokens (addressed in Workstream 1).

---

## Conventions

- Ruff, line length 100, Python 3.12.
- New policy condition: `app/policy/engine.py` + `validate_policy` + unit test.
- New ledger event: add to `EVENT_TYPES` in `app/ledger.py`, emit from service, test.
- New page: router in `app/web/routes.py`, template under `app/web/templates/`, sidebar link in `base.html`.
- Every schema change = Alembic migration.

---

## Session log (append-only, newest last)

### Session 1–3: Phases 0–2 (skeleton, core engine, UI)
See prior commit history.

### Session 4: 2026-10-10 – Phase 3 Demo
Seed, Demo Lab, SDK, smoke_test PASS.

### Session 5: 2026-10-10 – Phase 4 Polish
- Structured JSON logging (`app/logging_config.py`)
- Docker/Compose refreshed for Postgres
- `docs/DEMO_SCRIPT.md` (2-min + 5-min + judge Q&A)
- README completed (architecture, security, limitations, credits)
- Definition of Done checklist

### Session 6: 2026-10-12 – CodeX 3.0 hardening (Workstream 0+)
- Moved handoff/session log out of README → this file.
- README becomes clean pitch (problem, architecture, quickstart, threat model link, limitations).
- Removed `agentwarden.db-shm` from git tracking; already in `.gitignore`.
- Added `docs/THREAT_MODEL.md`.
- CI badge + consistent test reporting.
- Subsequent workstreams: param-bound approvals, decision tokens, gateway, stronger ledger, policy v2, accountability depth, demo polish.
