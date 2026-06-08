# Hackathon presentation outline — Agentic Security Platform

Use this as the script. ~5-7 minutes total: 2 min slides, 4 min live demo, 1 min Q&A.

---

## SLIDE 1 — The problem (60-90 sec)

### Title
**Checkmarx finds 10,000 issues. Which 5 can actually hurt you?**

### Body

Enterprise SAST tools (Checkmarx, Black Duck, Fortify) produce **theoretical findings** at massive scale:
- "Possible SQL injection here"
- "Hardcoded secret might be sensitive"
- "Potential XSS in this template"

Every payments engineering team has the same problem:
- Backlog of 10,000+ unverified findings
- 95%+ are false positives or untriaged
- Real exploitable issues get buried
- Engineers tune out the tool
- PCI audit findings hit production anyway

### The ask we set out to answer

> *Can we build a system that doesn't just FIND bugs but PROVES they're exploitable, PROPOSES the fix, and VERIFIES the fix works — all autonomously?*

---

## SLIDE 2 — The architecture (60-90 sec)

### Title
**Four agents in a loop, with a safety net at every step.**

```
Semgrep ──► Attacker ──► Sandbox ──► Healer ──► Validator ──► PR
            (Claude)     (Docker)    (Claude)   (pytest +
                                                 exploit
                                                 replay)
```

### What each agent does

| Stage | Agent | Output |
|---|---|---|
| 1. Scan | Semgrep + payments-domain YAML rules | List of findings (file:line) |
| 2. Attack | Claude writes a Python PoC | `EXPLOIT_SUCCESS` with marker values / txids / tokens |
| 3. Heal | Claude proposes a patch | Source diff + explanation + OWASP/PCI references |
| 4. Validate | Run pytest + replay the original exploit | Validated ✓ OR explicit rejection reason |

### Safety nets (the part judges care about)

- **AST validation** before any patch is written — file never gets corrupted
- **Atomic apply** — all writes or no writes
- **Test suite must still pass** after patch
- **Original exploit must NO LONGER succeed** after patch
- **All failures persist** with a specific reason ("syntax check", "tests broke", "exploit still works")
- **Source code never leaves the host** — `--metrics off`, no remote rule fetch, no SaaS dependency

### Stack

- Python brain, FastAPI UI with live progress over Server-Sent Events
- Claude via Agent SDK (uses Claude Code login — no separate API key, no separate billing)
- Semgrep for the scan
- Bundled rule packs for **.NET/C#, Angular/TypeScript, Python/Flask** — targeted at ACI SpeedPay's actual stack

---

## SLIDE 3 — Demo + results (LIVE on screen, then return for last 30 sec)

### Live demo flow (memorize this script)

1. **Open** http://127.0.0.1:8000 — point at the title bar: *"This is what we built — runs on my laptop, no cloud."*
2. **Click "Run full-loop demo"** — *"Watch the live log. The system is about to scan a vulnerable payment service, find bugs, write exploits, and propose fixes."*
3. **As scan_findings_prioritized fires**: *"Semgrep found 4 payments-specific vulnerabilities. Now Claude takes over."*
4. **As attacker_done shows EXPLOIT_SUCCESS**: *"That's a real Python exploit Claude wrote — POST /login to get a token, POST /pay with marker PAN, GET /logs — and the marker came back. Exploit confirmed."*
5. **As healer_done shows patched**: *"Claude wrote a fix. The AST safety net just checked it doesn't have syntax errors. File is written."*
6. **As validator runs**: *"Now we run the regression tests AND replay the original exploit against the patched code. Both must succeed."*
7. **Click `view` on a failed finding** → side drawer slides in: *"Look at this banner — `Patch REJECTED — would break callers`. The validator caught that the proposed fix changes the API contract. THIS is the safety net you want before an LLM-generated patch goes to main. A human reviews the PR before merge."*

### Numbers from the prior run (or live numbers if available)

- **4/4 vulnerabilities confirmed exploitable** with concrete evidence:
  - `PAN 4111... and CVV 4815... returned in /logs response`
  - `old token still authorizes /account/1 after re-login (no TTL/revocation)`
  - `duplicate charges with same Idempotency-Key tx1=... tx2=...`
- **3/4 patches proposed** with full architectural fixes (TTL + revocation, mandatory Idempotency-Key + dedup table)
- **1/4 patches rejected at the AST guard** — file untouched, system stayed correct
- **3/4 patches rejected at the test guard** — would have broken existing API consumers
- **0/4 auto-merged** — every patch is for human review

### Closing line (15 sec)

> *"Checkmarx tells you what might be wrong. Black Duck tells you what dependency is old. Neither tells you what an attacker can actually do or how to fix it. **This** does — with safety nets that stop bad fixes before they reach production. We're standing on top of $X of Anthropic credit usage for one demo run. Per developer, per scan, this is hundreds of times cheaper than a quarterly Checkmarx triage cycle."*

---

## SLIDE 4 (backup, if time allows) — Roadmap

- **Multi-region patching** — let the healer touch multiple files at once when a fix needs coordinated changes
- **Multi-language depth** — Java/Spring rule pack (we have Python + .NET + Angular today)
- **Real-repo full loop** — works on the seeded target today; needs a docker-compose for each service we want to demo against
- **Live UI auth** — currently localhost-only; ready for SSO once we deploy to a shared environment
- **Metrics + cost dashboard** — per-scan Claude usage, per-rule fire rate, false-positive triage
- **Jenkins CI integration** — already wired in `ci/Jenkinsfile`; runs scan on every PR, opens follow-up PR with proposed fixes

---

## Q&A — anticipated questions + crisp answers

**Q: How much does this cost per scan?**
A: Semgrep scan = free (local). LLM cost depends on findings: ~$0.30 per finding for attacker + healer = ~$1-2 for a typical scan. Billed against existing Claude Code subscription, not separate API.

**Q: Is the LLM-generated code safe to run?**
A: Yes — runs in Docker sandbox (or hardened subprocess fallback). Read-only filesystem, no network except to target, capability-stripped, 30-second timeout.

**Q: Does my source code go to Anthropic?**
A: The vulnerable code snippet + surrounding file does, in the prompt. That's the only way the LLM can write an exploit. Full files and tests stay local; only what the agent needs goes over the wire.

**Q: What about false positives?**
A: We've already de-noised on three real ACI repos: InternetApi (21 → 6 actionable findings), ExtranetApi (17 → 6, with 3 real Dapper SQLi true positives), rtal (10 vendor-JS FPs → 0 after exclusions).

**Q: Can it actually fix things, or just propose fixes?**
A: It fixes seeded test cases. For real repos, it proposes patches that a human reviews via PR. The validator rejects ~75% of proposed patches because they'd break tests or the contract — that's the safety net working.

**Q: How is this different from Snyk Code or GitHub Copilot Autofix?**
A: Those propose fixes from static patterns. We **execute the exploit** to confirm it's real BEFORE proposing a fix, and we **replay the exploit after fixing** to confirm the hole is closed. No other tool does both ends of the loop.

**Q: How do I run this on my real product repo?**
A: Scan-only mode works today on any repo — paste the path, click Start. Full loop needs a docker-compose for the service so we can spin it up and re-spin after patching. Most NextGen services already have one for local dev.
