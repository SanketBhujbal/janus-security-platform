# Agentic Security Platform

Payments-domain SAST + autonomous PoC + LLM-driven patching, with a regression-test safety net.
**Built to outperform Checkmarx / Black Duck for one specific class of problem: catching real exploitable bugs and producing actionable proposed fixes with concrete evidence.**

---

## What it does (in one sentence)

For every Semgrep finding on your code, an LLM **writes and runs a real PoC exploit** in a sandbox to confirm it's exploitable; if it is, a second LLM **proposes a fix**; a third agent **verifies the fix didn't break tests AND replays the exploit** to confirm the hole is closed; only then is a PR opened.

---

## Architecture

```
                    ┌──────────────────────────────────────────────────────┐
                    │              SECURITY BRAIN (orchestrator)           │
                    │                                                      │
   ┌─────────┐      │   1. SCAN          2. ATTACK       3. HEAL           │
   │  Your   │      │   ┌─────────┐    ┌─────────┐    ┌─────────┐          │
   │  Repo   │ ───► │   │ Semgrep │ ─► │Attacker │ ─► │ Healer  │          │
   │ (.py /  │      │   │ + YAML  │    │ (Claude)│    │ (Claude)│          │
   │  .cs /  │      │   │  rules  │    │         │    │         │          │
   │  .ts)   │      │   └─────────┘    └────┬────┘    └────┬────┘          │
   └─────────┘      │                       │              │               │
                    │                       ▼              ▼               │
                    │                  ┌─────────┐    ┌─────────┐          │
                    │                  │ Sandbox │    │   AST   │          │
                    │                  │ Runner  │    │ Safety  │          │
                    │                  │(Docker /│    │  Check  │          │
                    │                  │subproc) │    │         │          │
                    │                  └─────────┘    └────┬────┘          │
                    │                                      │               │
                    │                                      ▼               │
                    │                                4. VALIDATE           │
                    │                                ┌─────────┐           │
                    │                                │Validator│           │
                    │                                │ - tests │           │
                    │                                │ - replay│           │
                    │                                └────┬────┘           │
                    └─────────────────────────────────────┼────────────────┘
                                                          │
                                                          ▼
                                                ┌──────────────────┐
                                                │  report.json +   │
                                                │  GitHub PR with  │
                                                │  PoC + diff +    │
                                                │  explanation     │
                                                └──────────────────┘
```

| Component | Tech | What it does |
|---|---|---|
| **Scan** | Semgrep + bundled YAML rules | Pattern-matches payments-domain vulnerabilities across Python, C#/.NET, TypeScript/Angular |
| **Attacker** | Claude (via Agent SDK) | Writes a Python PoC that hits the running target, prints `EXPLOIT_SUCCESS` with concrete evidence |
| **Sandbox Runner** | Docker container OR Python subprocess | Isolated execution of LLM-generated exploits |
| **Healer** | Claude (via Agent SDK) | Proposes a patch; AST-validated before writing |
| **Validator** | pytest + sandbox replay | Tests must pass AND original exploit must no longer succeed |
| **Web UI** | FastAPI + SSE + vanilla JS | Real-time scan progress, findings table, detail drawer |

---

## Why this beats Checkmarx / Black Duck for the same job

| Capability | Checkmarx | Black Duck | This |
|---|---|---|---|
| Find theoretical issues | ✓ | partial | ✓ |
| Prove issue is **exploitable** | ✗ | ✗ | ✓ (live PoC) |
| Auto-generate PoC code | ✗ | ✗ | ✓ |
| Propose a patch | ✗ | ✗ | ✓ |
| Validate patch doesn't break tests | ✗ | ✗ | ✓ |
| Re-test patch with original exploit | ✗ | ✗ | ✓ |
| Open a PR with all of the above attached | ✗ | ✗ | ✓ |
| Domain-tuned for payments (PCI, idempotency, PAN/CVV) | generic | generic | ✓ |

---

## Bundled payments rules

| Stack | Rules | Examples |
|---|---|---|
| **Python / Flask** | 7 | PAN/CVV in logger, missing idempotency, broken authz, amount tampering, duplicate-payment, session-misuse, weak-payment-validation |
| **.NET / C#** | 11 | `SqlCommand` interpolation, EF Core `FromSqlRaw`, Dapper SQLi (`QueryAsync<T>($"...")`), PAN/CVV in `ILogger`, missing-idempotency on EF, broken-authz-IDOR, webhook-amount-trust, weak-JWT, ContextIdentity-unchecked-cast, conn-string-with-password, API-key-in-appsettings |
| **Angular / TypeScript** | 5 | `bypassSecurityTrustHtml`, `innerHTML` user data, card-data in localStorage, auth-token in localStorage, ngx-webstorage tokens, console.log of PAN/CVV, client-amount POSTed to /pay |

---

## Run it

```powershell
cd C:\Users\bhujbalsa\security_orchestrator
pip install -r requirements.txt
pip install semgrep flask claude-agent-sdk
python -m webapp                                   # opens http://127.0.0.1:8000
```

| Form action | What happens |
|---|---|
| Paste a repo path → **Start scan** | Scan-only on your real code (no Docker, no LLM cost) |
| Click **Run full-loop demo** | Full attack→patch→validate on the seeded vulnerable Flask app |

---

## Repo layout

```
orchestrator/           # the brain
  agents/               #   attacker, healer, validator, base
  scanners/             #   Semgrep wrapper
  rules/                #   payments YAML rule packs (Python / .NET / Angular)
  exploits/             #   sandbox runners (Docker + subprocess)
  sandbox/              #   target deployers (Docker compose + subprocess)
  llm/                  #   Anthropic API + Claude Agent SDK clients
  state/                #   cross-run history (skip already-validated findings)
  events.py             #   structured event stream for SSE
  models/vulnerability.py
  orchestrator.py       #   SecurityBrain - the coordinator

webapp/                 # FastAPI + vanilla JS UI
  api.py                #   REST + SSE endpoints
  manager.py            #   ScanRunner + ScanManager (workers + queues)
  static/               #   index.html, style.css, app.js
  store.py              #   persistent scan store (survives restarts)

sandbox/                # seeded vulnerable targets (do NOT deploy)
  target-api/           #   Python/Flask app with 7 deliberate vulns
  target-dotnet/        #   C# seeded app (rule verification only, no runtime)
  target-angular/       #   Angular seeded app (rule verification only)

tests/                  # 35 unit tests
scripts/                # demo CLI + scan CLI + helper scripts
ci/Jenkinsfile          # CI/CD integration
```

---

## Built for ACI SpeedPay's stack

- **.NET 8 + Dapper + SQL Server** — rules tuned to actual SpeedPay patterns (Dapper interpolated SQL, `ContextIdentity` custom auth, `AllowRoleAttribute`)
- **Angular 19** — Internet-UI patterns, ngx-webstorage abstraction
- **Payments domain** — PCI DSS 3.2 / 6.5 references in every rule
- **Behind your corporate TLS-inspecting proxy** — Semgrep `--metrics off`, `--disable-version-check`, no remote rule fetches; source code never leaves the host

---

## Limitations (honest)

| Limitation | Workaround / future fix |
|---|---|
| Healer modifies one snippet at a time. Fixes that need cross-region changes (e.g. updating `current_user()` when `TOKENS` shape changes) leave callers broken | Multi-region healer (next iteration) |
| Without Docker, exploits run unsandboxed on the host (only safe for trusted seeded targets) | Install Docker Desktop; production usage is Docker-only |
| Patches that break the regression test contract get rejected by the validator | This is **a feature**, not a bug — human review before merge |
| Multi-language rule coverage is uneven (Python and .NET deepest; Java planned) | Add language-specific rule packs as needed |
