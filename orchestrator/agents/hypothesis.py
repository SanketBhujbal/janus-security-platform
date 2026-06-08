"""HypothesisAgent — cross-file vulnerability chain detection.

Runs once per scan AFTER findings are collected but BEFORE the per-finding
exploit loop.  It reads the prioritized finding list + key repo files and asks
the LLM to identify which findings could be combined into a higher-severity
multi-step attack.

Output: a list of AttackChain objects, each grouping 2+ finding fingerprints
with a combined severity and an attack narrative.  The orchestrator stores the
chains in the report and applies a chain_severity_boost to each involved finding.
"""
from __future__ import annotations

import json
import logging
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..llm.claude_client import LLMClient
from ..models.vulnerability import Severity, Vulnerability
from .base import AgentContext


log = logging.getLogger("security_brain.hypothesis")

_MIN_FINDINGS_FOR_CHAIN_ANALYSIS = 2
_MAX_FILES_TO_INCLUDE = 4
_MAX_FILE_CHARS = 3000

HYPOTHESIS_SYSTEM = """You are a senior red-team architect analyzing a set of individually-discovered \
vulnerabilities in a payments application. Your task is to identify ATTACK CHAINS — \
sequences of 2 or more findings that an attacker could combine into a single, higher-severity \
attack.

Rules:
- Only chain findings that have a plausible sequential dependency (e.g. "log the PAN first, \
  then use the leaked PAN to tamper an amount").
- Assign the chain a severity that is at least as high as the highest-severity component \
  (escalate if the combination meaningfully raises impact).
- Write a concise, realistic attack_narrative (3-6 sentences).
- If no meaningful chains exist, return an empty list.

Respond with STRICT JSON only (no prose, no fences):
[
  {
    "chain_id": "<short-kebab-slug>",
    "title": "<one-line chain title>",
    "severity": "<critical|high|medium|low>",
    "fingerprints": ["<fp1>", "<fp2>"],
    "attack_narrative": "<step-by-step attack description>",
    "combined_impact": "<1-2 sentences on the business/financial impact>"
  }
]
"""


@dataclass
class AttackChain:
    chain_id: str
    title: str
    severity: str
    fingerprints: list[str]
    attack_narrative: str
    combined_impact: str
    member_vulns: list[Vulnerability] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "severity": self.severity,
            "fingerprints": self.fingerprints,
            "attack_narrative": self.attack_narrative,
            "combined_impact": self.combined_impact,
        }


class HypothesisAgent:
    name = "hypothesis"

    def __init__(self, llm: LLMClient):
        self.llm = llm

    def run(
        self, findings: list[Vulnerability], ctx: AgentContext
    ) -> list[AttackChain]:
        if len(findings) < _MIN_FINDINGS_FOR_CHAIN_ANALYSIS:
            log.info("hypothesis: only %d finding(s) — skipping chain analysis", len(findings))
            return []

        finding_summary = self._summarize_findings(findings)
        repo_context = self._read_key_files(ctx.repo_root)

        user_prompt = textwrap.dedent(
            f"""
            Repository: {ctx.repo_root}

            === FINDINGS ({len(findings)} total) ===
            {finding_summary}

            === KEY SOURCE FILES ===
            {repo_context}

            Identify all exploitable attack chains across these findings.
            """
        ).strip()

        try:
            raw = self.llm.complete_json(HYPOTHESIS_SYSTEM, user_prompt)
        except Exception as e:
            log.warning("hypothesis: LLM call failed: %s", e)
            return []

        if not isinstance(raw, list):
            log.warning("hypothesis: unexpected LLM response type %s", type(raw))
            return []

        fp_to_vuln = {v.fingerprint: v for v in findings}
        chains: list[AttackChain] = []
        for item in raw:
            try:
                chain = self._parse_chain(item, fp_to_vuln)
                if chain is not None:
                    chains.append(chain)
            except Exception as e:
                log.debug("hypothesis: skipped malformed chain entry: %s", e)

        log.info("hypothesis: identified %d attack chain(s)", len(chains))
        return chains

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _summarize_findings(self, findings: list[Vulnerability]) -> str:
        lines = []
        for v in findings:
            lines.append(
                f"  fingerprint={v.fingerprint}  category={v.category.value}  "
                f"severity={v.severity.value}  location={v.location.as_pointer()}\n"
                f"  title: {v.title}\n"
                f"  description: {v.description[:200]}\n"
            )
        return "\n".join(lines)

    def _read_key_files(self, repo_root: Path) -> str:
        """Include entry-point + route files for chain reasoning."""
        candidates: list[Path] = []
        priority_names = {"program.cs", "app.py", "main.py", "startup.cs", "urls.py",
                          "routes.py", "index.ts", "index.js", "server.ts", "server.js"}
        for ext in ("*.py", "*.cs", "*.java", "*.ts", "*.js"):
            for f in repo_root.rglob(ext):
                if f.name.lower() in priority_names:
                    candidates.insert(0, f)
                else:
                    candidates.append(f)

        excerpts: list[str] = []
        seen: set[Path] = set()
        for f in candidates:
            if f.resolve() in seen or len(excerpts) >= _MAX_FILES_TO_INCLUDE:
                break
            seen.add(f.resolve())
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if len(text) > _MAX_FILE_CHARS:
                text = text[:_MAX_FILE_CHARS] + "\n...(truncated)"
            try:
                rel = f.relative_to(repo_root)
            except ValueError:
                rel = f.name
            excerpts.append(f"// {rel}\n{text}")

        return "\n---\n".join(excerpts) if excerpts else "(no source files found)"

    def _parse_chain(
        self, item: dict, fp_to_vuln: dict[str, Vulnerability]
    ) -> AttackChain | None:
        fingerprints = [str(fp) for fp in (item.get("fingerprints") or []) if fp]
        members = [fp_to_vuln[fp] for fp in fingerprints if fp in fp_to_vuln]
        if len(members) < 2:
            return None
        chain = AttackChain(
            chain_id=str(item.get("chain_id") or "chain"),
            title=str(item.get("title") or "Attack Chain"),
            severity=str(item.get("severity") or "high"),
            fingerprints=fingerprints,
            attack_narrative=str(item.get("attack_narrative") or ""),
            combined_impact=str(item.get("combined_impact") or ""),
            member_vulns=members,
        )
        # Tag each member finding so the report can show chain membership
        for v in members:
            v.metadata.setdefault("chains", []).append(chain.chain_id)
            # Optionally boost severity if the chain escalates it
            try:
                chain_sev = Severity(chain.severity)
                sev_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
                if sev_order.index(chain_sev) > sev_order.index(v.severity):
                    v.metadata["chain_severity_boost"] = chain.severity
            except (ValueError, AttributeError):
                pass
        return chain
