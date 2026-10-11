# AgentWarden – Demo Scripts

For CodeX 3.0 judges. Run `make seed` and `make run` before starting.  
Login: **admin@demo.local** / **demo-admin-pass**

---

## 2-minute demo (elevator)

| Time | Action | What to say |
|------|--------|-------------|
| 0:00 | Open Overview | “AgentWarden sits between AI agents and the tools they use. Rules decide—never an LLM.” |
| 0:20 | Point at ledger badge + OPERATIONAL pill | “Every event is hash-chained. The badge is live.” |
| 0:30 | Demo Lab → **Small refund** | “Forty dollars: auto-allowed by priority-10 rule.” |
| 0:45 | Demo Lab → **Large refund** | “Nine hundred dollars: requires approval.” |
| 0:55 | Approvals as **reviewer_b** (not the owner) | “Separation of duties: the agent’s owner cannot approve.” |
| 1:15 | Demo Lab → **Leak customer data** | “External PII email: hard deny. Matched rule is shown.” |
| 1:25 | Ledger → **Verify** | “Watch the chain light up green. PASS.” |
| 1:35 | Demo Lab → **Tamper**, then Verify | “Stops on the red block with expected vs found hash.” |
| 1:50 | Toggle **Judge** (header) | “Projector-friendly type size.” |
| 1:55 | Close | “Named human owners, written reasons, default deny.” |

---

## 5-minute demo (full story)

### Setup (before judges arrive)
1. `PYTHONPATH=. python scripts/seed.py --reset`
2. `uvicorn app.main:app --port 8000`
3. Browser at `/login`, optionally second window as reviewer_b

### Script

**1. Problem (30s)**  
Overview page. “Agents get refund and email authority. Without governance you cannot answer: was this allowed, under which rule, who is responsible, and can the record be trusted?”

**2. Policy engine (45s)**  
Policies page. Show active JSON. “Pure function, default deny, lowest priority wins. No LLM in the decision path.”

**3. Happy path (60s)**  
Demo Lab: small refund → Live Feed updates. Large refund → Approvals queue. Switch to reviewer_b → approve with a written reason (≥10 chars). Owner (reviewer_a) sees buttons disabled.

**4. Deny + rate limit (45s)**  
Demo Lab: leak → denied. Burst → later calls denied by rate_limit condition.

**5. Escalation (30s)**  
Demo Lab: “Make approval overdue” (45s SLA). Wait or advance clock narrative → Escalated tab.

**6. Accountability (30s)**  
Agents → refund-bot → owner name, timeline of who decided what.

**7. Ledger integrity (60s)**  
Ledger → Verify PASS. Tamper → Verify FAIL with seq highlight. Repair → PASS. Checkpoint download: “HMAC so an outsider can detect a full-chain rewrite.”

**8. Close (20s)**  
“Honest limits: ledger is tamper-evident; sensitivity is agent-declared. Scope is governance, not multi-tenant SaaS.”

---

## Likely judge questions (honest answers)

**How does verification work?**  
Each entry stores `prev_hash` and `hash = sha256(prev_hash + canonical_json(fields))`. `verify()` walks seq 1…N and recomputes. Detects edited payload, edited hash, seq gaps, and bad prev links.

**What stops someone rewriting the whole database?**  
Nothing inside the DB alone. That is why checkpoints exist: export `{seq, hash, ts, hmac}` with a key held outside the DB. After a rewrite, HMAC or entry hash no longer matches. Tamper-evident, not tamper-proof—say so explicitly.

**What happens with two simultaneous requests?**  
Ledger append locks `LedgerHead` (`SELECT FOR UPDATE` on Postgres; write lock on SQLite) in the same transaction as the business write, so two appends cannot share the same `prev_hash`.

**Why not use an LLM to judge actions?**  
Non-negotiable product rule: decisions must be deterministic and auditable. An LLM may only reword a pending-request summary when `ANTHROPIC_API_KEY` is set. The app works 100% without any API key.

**Is the agent trusted to declare sensitivity?**  
No. Self-declared sensitivity is a known limitation. Production deployments should classify data server-side; we document the gap.

**Can the owner approve their own agent?**  
No. Enforced in the service layer (not only the UI), covered by tests.

**Default when no rule matches?**  
DENY.

---

## Recovery if something breaks mid-demo

```bash
PYTHONPATH=. python scripts/seed.py --reset
# or Demo Lab → Repair after a tamper
PYTHONPATH=. python scripts/tamper.py --repair
```
