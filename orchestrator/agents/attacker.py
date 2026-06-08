from __future__ import annotations

import logging
import textwrap

from ..exploits.runner import SandboxRunner
from ..llm.claude_client import LLMClient
from ..models.vulnerability import (
    Exploit,
    FindingStatus,
    VulnCategory,
    Vulnerability,
)
from .base import Agent, AgentContext


log = logging.getLogger("security_brain.attacker")

MAX_EXPLOIT_RETRIES = 3


ATTACKER_SYSTEM = """You are an offensive security engineer producing a SINGLE proof-of-concept exploit \
for a vulnerability already discovered in source code. You will produce a Python script that exercises \
the vulnerability against a target endpoint.

Hard requirements for the script:
1. Use only `requests` (pre-installed in the sandbox).
2. Read base URL from env var TARGET_URL.
3. On success print exactly: EXPLOIT_SUCCESS: <one-line evidence>
4. On failure print exactly: EXPLOIT_FAIL: <one-line reason>
5. Always exit 0. We parse stdout for the verdict.
6. Total runtime must stay under 5 seconds. No sleeps > 1s. No interactive prompts.
7. Do not perform destructive actions beyond what is strictly required to demonstrate the flaw.
8. No network targets other than TARGET_URL.

Respond with STRICT JSON only (no prose, no code fences):
{
  "payload": "<short description of the payload>",
  "expected_signal": "<observable that proves the exploit worked>",
  "script": "<full python script as a single string>"
}
"""


CATEGORY_HINTS: dict[VulnCategory, str] = {
    VulnCategory.SQL_INJECTION: (
        "Try classic UNION-based and boolean-based injection. Look for reflected data, "
        "extra rows, or auth bypass via OR 1=1."
    ),
    VulnCategory.NOSQL_INJECTION: (
        "Use $ne / $gt / $regex operators in JSON bodies against MongoDB-style queries."
    ),
    VulnCategory.AMOUNT_TAMPERING: (
        "Submit a payment with negative, zero, or grossly mismatched amount and check it is "
        "accepted on the server side without reconciling against a trusted price/order record."
    ),
    VulnCategory.DUPLICATE_PAYMENT: (
        "Replay the same payment POST rapidly with identical idempotency key (or none). "
        "Success = the same intent debits twice or returns two distinct charge IDs."
    ),
    VulnCategory.MISSING_IDEMPOTENCY: (
        "Send the same mutating POST twice with identical bodies and no Idempotency-Key header. "
        "Success = two side effects (two transactions, two orders, etc)."
    ),
    VulnCategory.BROKEN_AUTHZ: (
        "Authenticate as user A and access /resource/{B_id}. Success = data for B is returned "
        "or modified despite the token not belonging to B."
    ),
    VulnCategory.SENSITIVE_LOGGING: (
        "Submit a transaction with a marker PAN/CVV value (e.g. PAN=4111111111111111, CVV=123). "
        "Then hit a log/health/debug endpoint and check the marker is echoed back."
    ),
    VulnCategory.WEAK_PAYMENT_VALIDATION: (
        "Try missing required fields, wrong currency code, oversized amounts, non-ASCII names. "
        "Success = transaction accepted with clearly invalid input."
    ),
    VulnCategory.SESSION_MISUSE: (
        "Reuse a token after logout, use an expired token, or use a token issued for user A as user B."
    ),
    VulnCategory.LOGIC_FLAW: (
        "Look for state-machine bypasses: skip a step, double-trigger a step, or order steps out of sequence."
    ),
}


class AttackerAgent(Agent):
    name = "attacker"

    def __init__(self, llm: LLMClient, sandbox: SandboxRunner):
        super().__init__(llm)
        self.sandbox = sandbox

    def run(self, vuln: Vulnerability, ctx: AgentContext) -> Vulnerability:
        prior_attempts: list[dict] = []
        exploit: Exploit | None = None

        for attempt in range(MAX_EXPLOIT_RETRIES):
            spec = self._generate_exploit(vuln, ctx, prior_attempts=prior_attempts)
            exploit = Exploit(
                category=vuln.category,
                payload=spec.get("payload", ""),
                script=spec["script"],
                endpoint=ctx.target_endpoint,
                expected_signal=spec.get("expected_signal", "EXPLOIT_SUCCESS"),
            )

            verdict = self.sandbox.run_python_exploit(
                script=exploit.script,
                target_url=ctx.target_endpoint or "",
                timeout_s=30,
            )
            exploit.sandbox_logs = verdict.logs
            exploit.actual_signal = verdict.stdout.strip()
            exploit.succeeded = "EXPLOIT_SUCCESS" in verdict.stdout

            if exploit.succeeded:
                if attempt > 0:
                    log.info("attacker: exploit succeeded on attempt %d/%d", attempt + 1, MAX_EXPLOIT_RETRIES)
                break

            log.info(
                "attacker: attempt %d/%d failed (output=%r); retrying with failure context",
                attempt + 1, MAX_EXPLOIT_RETRIES, exploit.actual_signal[:80] if exploit.actual_signal else "",
            )
            prior_attempts.append({
                "attempt": attempt + 1,
                "payload": spec.get("payload", ""),
                "actual_output": (exploit.actual_signal or "")[:200],
                "logs": (verdict.logs or "")[:300],
            })

        vuln.exploit = exploit
        vuln.exploitability = 1.0 if exploit.succeeded else 0.1
        vuln.status = FindingStatus.EXPLOITED if exploit.succeeded else FindingStatus.DISCOVERED
        attempts_note = f" (attempt {len(prior_attempts) + 1}/{MAX_EXPLOIT_RETRIES})" if prior_attempts else ""
        vuln.notes.append(
            f"attacker: {'PoC succeeded' if exploit.succeeded else 'PoC did not reproduce'}"
            f"{attempts_note} (category={vuln.category.value})"
        )
        return vuln

    def _generate_exploit(
        self,
        vuln: Vulnerability,
        ctx: AgentContext,
        prior_attempts: list[dict] | None = None,
    ) -> dict:
        hint = CATEGORY_HINTS.get(
            vuln.category, "Generate the most realistic exploit for this category."
        )
        # The vulnerable snippet alone often leaves the LLM blind to required
        # prerequisites like /login flows. Include the surrounding file so the
        # LLM can chain calls (login -> mutate -> read) when needed.
        file_excerpt = self._read_file_excerpt(vuln.location.file, max_chars=6000)

        retry_section = ""
        if prior_attempts:
            lines = ["\nPREVIOUS FAILED ATTEMPTS — study these and use a DIFFERENT approach:\n"]
            for a in prior_attempts:
                lines.append(
                    f"  Attempt {a['attempt']}: payload={a['payload']!r}\n"
                    f"    stdout: {a['actual_output']!r}\n"
                    f"    logs:   {a['logs']!r}\n"
                )
            lines.append(
                "Change the HTTP method, path, headers, or payload structure. "
                "Do NOT produce the same script again.\n"
            )
            retry_section = "".join(lines)

        # Inject known-working hints from prior runs if available
        kb_hints = self._get_kb_hints(vuln)
        kb_section = ""
        if kb_hints:
            kb_section = (
                "\nKnown-working approaches from previous runs on similar targets "
                "(use as inspiration, adapt to this endpoint):\n"
                + "\n".join(f"  - {h}" for h in kb_hints[:3])
                + "\n"
            )

        user = textwrap.dedent(
            f"""
            Vulnerability category: {vuln.category.value}
            Severity: {vuln.severity.value}
            Title: {vuln.title}
            Description: {vuln.description}
            Source location: {vuln.location.as_pointer()}
            Vulnerable code snippet:
            ---
            {vuln.location.snippet}
            ---
            Surrounding file context (read this to discover required auth /
            login flows and adjacent endpoints you may need to call first):
            ---
            {file_excerpt}
            ---
            Target endpoint base URL: {ctx.target_endpoint or '(none provided — use env TARGET_URL)'}
            Strategy hint: {hint}
            {kb_section}{retry_section}
            IMPORTANT:
            - If POST endpoints require auth (look for `Authorization`, `Bearer`,
              `current_user`, `401`), perform the login / token acquisition
              flow FIRST using any seeded credentials visible in the file
              (e.g. usernames + passwords in DB seed statements).
            - Use those credentials only if they are clearly seeded test data.
            """
        ).strip()
        return self.llm.complete_json(ATTACKER_SYSTEM, user)

    def _get_kb_hints(self, vuln: Vulnerability) -> list[str]:
        """Return known-working exploit hints from the attack knowledge base."""
        try:
            from ..state.exploit_kb import ExploitKnowledgeBase
            kb_path = vuln.location.file.parent / ".security_workdir" / "exploit_kb.json"
            if not kb_path.exists():
                # Try repo root
                kb_path = vuln.location.file.parents[2] / ".security_workdir" / "exploit_kb.json"
            if kb_path.exists():
                kb = ExploitKnowledgeBase(kb_path)
                return kb.get_hints(vuln.category)
        except Exception:
            pass
        return []

    @staticmethod
    def _read_file_excerpt(path, max_chars: int = 6000) -> str:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "(could not read file)"
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + f"\n... (file truncated, {len(text) - max_chars} chars omitted)"
