"""EfficiencyBrain — the orchestrator for the efficiency mission.

Twin of SecurityBrain. Runs profile -> refactor -> verify on a target
codebase and emits the same event protocol so the existing webapp/SSE
UI can render its progress with no extra glue.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .agents.base import AgentContext
from .agents.refactor import RefactorAgent
from .agents.verifier import VerifierAgent
from .events import (
    AGENT_DONE,
    AGENT_START,
    EventCallback,
    FINDING_COMPLETED,
    FINDING_DISCOVERED,
    PR_OPENED,
    SCAN_DONE,
    SCAN_FINDINGS_PRIORITIZED,
    SCAN_FINDINGS_RAW,
    SCAN_START,
    noop_emitter,
)
from .llm.claude_client import LLMClient
from .models.perf import PerfFinding, PerfStatus, SavingsConfig
from .models.vulnerability import Severity
from .perf_history import PerfHistory
from .scanners.perf_scanner import PerfScanner


log = logging.getLogger("efficiency_brain")


@dataclass
class PerfReport:
    scanned: int = 0
    refactored: int = 0
    verified: int = 0
    failed: int = 0
    total_annual_dollars: float = 0.0
    total_annual_co2_grams: float = 0.0
    findings: list[PerfFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "mode":                "efficiency",
            "scanned":             self.scanned,
            "refactored":          self.refactored,
            "verified":            self.verified,
            "failed":              self.failed,
            "total_annual_dollars": round(self.total_annual_dollars, 2),
            "total_annual_co2_grams": round(self.total_annual_co2_grams, 2),
            "findings":            [f.to_dict() for f in self.findings],
        }


class EfficiencyBrain:
    def __init__(
        self,
        repo_root: Path,
        rules_dir: Path,
        llm: LLMClient | None,
        runner,                                # SubprocessRunner duck-type
        max_findings_per_run: int = 10,
        calls_per_year: int = 3_600_000,
        savings_config: SavingsConfig | None = None,
        on_event: EventCallback | None = None,
        scan_only: bool = False,
        github_repo_slug: str | None = None,
        github_token: str | None = None,
        github_base_branch: str = "main",
        pr_provider: str = "github",           # "github" | "bitbucket"
        bitbucket_workspace: str | None = None,
        bitbucket_repo_slug: str | None = None,
        bitbucket_token: str | None = None,
        profile_hints: dict | None = None,     # runtime profile import (P7)
        history_enabled: bool = True,          # cumulative savings history (P8)
    ):
        self.repo_root = repo_root.resolve()
        self.rules_dir = rules_dir
        self.scanner = PerfScanner(rules_dir=rules_dir)
        self.scan_only = scan_only
        self.savings_config = savings_config or SavingsConfig(calls_per_year=calls_per_year)
        # In scan-only mode we never call the LLM and never run the benchmark,
        # so we don't need a real LLM client or runner -- skip building agents.
        if scan_only:
            self.refactor = None
            self.verifier = None
        else:
            assert llm is not None, "EfficiencyBrain needs an LLM unless scan_only=True"
            self.refactor = RefactorAgent(llm)
            self.verifier = VerifierAgent(llm, runner, savings_config=self.savings_config)
        self.max_findings_per_run = max_findings_per_run
        self._emit_raw = on_event or noop_emitter
        self.github_repo_slug = github_repo_slug
        self.github_token = github_token
        self.github_base_branch = github_base_branch
        self.pr_provider = (pr_provider or "github").lower()
        self.bitbucket_workspace = bitbucket_workspace
        self.bitbucket_repo_slug = bitbucket_repo_slug
        self.bitbucket_token = bitbucket_token
        self.profile_hints = profile_hints or {}
        self.history_enabled = history_enabled

    def _emit(self, type: str, message: str, **data) -> None:
        try:
            self._emit_raw(type, message, **data)
        except Exception:
            log.exception("event emit failed")

    def run_efficiency_loop(self) -> PerfReport:
        report = PerfReport()
        ctx = AgentContext(repo_root=self.repo_root, target_endpoint=None)

        self._emit(
            SCAN_START,
            f"profiling {self.repo_root} for efficiency",
            repo=str(self.repo_root),
            mode="efficiency",
        )
        raw = self.scanner.scan(self.repo_root)
        self._emit(SCAN_FINDINGS_RAW,
                   f"profiler returned {len(raw)} candidate(s)",
                   count=len(raw))
        # Prioritize: HIGH severity hot-paths first, then MEDIUM, etc.
        prioritized = sorted(
            raw,
            key=lambda f: ([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                            Severity.LOW, Severity.INFO].index(f.severity)),
        )
        prioritized = prioritized[: self.max_findings_per_run]
        report.scanned = len(prioritized)
        self._emit(
            SCAN_FINDINGS_PRIORITIZED,
            f"prioritized {len(prioritized)} candidate(s) for refactor",
            count=len(prioritized),
        )

        for idx, finding in enumerate(prioritized):
            self._apply_profile_hint(finding)
            self._emit(
                FINDING_DISCOVERED,
                f"{finding.category.value} @ {finding.location.as_pointer()}",
                idx=idx,
                category=finding.category.value,
                severity=finding.severity.value,
                location=finding.location.as_pointer(),
                rule_id=finding.rule_id or "",
                title=finding.title,
                function_name=finding.function_name,
                language=finding.language,
                fingerprint=finding.fingerprint,
                calls_per_year=finding.calls_per_year_override or self.savings_config.calls_per_year,
                status=finding.status.value,
            )

            if self.scan_only:
                # Profile-only mode: just record the finding, no LLM, no bench.
                report.findings.append(finding)
                self._emit(
                    FINDING_COMPLETED, f"finding #{idx}: {finding.status.value}",
                    idx=idx, status=finding.status.value,
                )
                continue

            try:
                self._emit(AGENT_START, "refactor: generating optimized code",
                           agent="refactor", idx=idx)
                finding = self.refactor.run_finding(finding, ctx)
                self._emit(AGENT_DONE, f"refactor: {finding.status.value}",
                           agent="refactor", idx=idx, status=finding.status.value)

                if finding.status == PerfStatus.REFACTORED:
                    self._emit(AGENT_START, "verifier: running benchmark + output check",
                               agent="verifier", idx=idx)
                    finding = self.verifier.run_finding(finding, ctx)
                    self._emit(AGENT_DONE, f"verifier: {finding.status.value}",
                               agent="verifier", idx=idx, status=finding.status.value)

                if finding.status == PerfStatus.VERIFIED:
                    report.verified += 1
                    if finding.savings:
                        report.total_annual_dollars   += finding.savings.annual_dollars
                        report.total_annual_co2_grams += finding.savings.annual_co2_grams
                elif finding.status == PerfStatus.REFACTORED:
                    report.refactored += 1
                else:
                    report.failed += 1
            except Exception as e:
                log.exception("efficiency_brain: finding %d crashed", idx)
                finding.status = PerfStatus.FAILED
                finding.notes.append(f"brain: {type(e).__name__}: {e}")
                report.failed += 1

            report.findings.append(finding)
            self._emit(
                FINDING_COMPLETED, f"finding #{idx}: {finding.status.value}",
                idx=idx, status=finding.status.value,
            )

        self._write_report(report)
        self._update_history(report)
        self._try_open_pr(report)
        self._emit(SCAN_DONE, "efficiency scan finished", summary=report.to_dict())
        return report

    def _apply_profile_hint(self, finding: PerfFinding) -> None:
        """Runtime profile import (P7): if a profile told us how hot this exact
        function is, use that call rate for the savings projection instead of the
        global default. Hints are keyed by fingerprint OR function name."""
        if not self.profile_hints:
            return
        hint = (self.profile_hints.get(finding.fingerprint)
                or self.profile_hints.get(finding.function_name))
        if not hint:
            return
        try:
            calls = int(hint.get("calls_per_year") if isinstance(hint, dict) else hint)
        except (TypeError, ValueError):
            return
        if calls > 0:
            finding.calls_per_year_override = calls
            src = hint.get("source", "runtime profile") if isinstance(hint, dict) else "runtime profile"
            finding.runtime_hint_note = f"{calls:,} calls/yr from {src}"
            finding.notes.append(f"profile: {finding.runtime_hint_note}")

    def _update_history(self, report: PerfReport) -> None:
        if not self.history_enabled:
            return
        try:
            hist = PerfHistory(self.repo_root)
            added = hist.record_run(report.to_dict())
            totals = hist.totals()
            self._emit(
                "history_updated",
                f"lifetime verified: {totals['verified_count']} finding(s), "
                f"${totals['total_annual_dollars']:,.2f}/yr, "
                f"{totals['total_annual_co2_grams']:,.0f} g CO₂/yr",
                added=added,
                repo=str(self.repo_root),
                **totals,
            )
        except Exception as e:
            log.warning("efficiency_brain: history update failed: %s", e)

    def _try_open_pr(self, report: PerfReport) -> None:
        verified = [f for f in report.findings if f.status == PerfStatus.VERIFIED]
        if not verified:
            log.info("efficiency_brain: no verified findings — skipping PR")
            return
        try:
            creator = self._build_pr_creator()
            if creator is None:
                return
            pr_url = creator.create_pr_from_perf_report(self.repo_root, report.to_dict())
            if pr_url:
                self._emit(PR_OPENED, f"PR opened: {pr_url}", url=pr_url, count=len(verified))
        except Exception as e:
            log.warning("efficiency_brain: PR creation skipped: %s", e)
            self._emit(PR_OPENED, f"PR skipped: {e}", url="", count=0, error=str(e))

    def _build_pr_creator(self):
        """Pick a PR backend. Bitbucket when configured (ACI's primary SCM),
        else GitHub. Both expose create_pr_from_perf_report(repo_root, dict)."""
        if self.pr_provider == "bitbucket" and self.bitbucket_workspace and self.bitbucket_repo_slug:
            from .git_ops.bitbucket_pr import BitbucketEfficiencyPRCreator
            return BitbucketEfficiencyPRCreator(
                workspace=self.bitbucket_workspace,
                repo_slug=self.bitbucket_repo_slug,
                token=self.bitbucket_token,
                base_branch=self.github_base_branch,
            )
        if self.github_repo_slug:
            from .git_ops.github_pr import GitHubEfficiencyPRCreator
            return GitHubEfficiencyPRCreator(
                repo_slug=self.github_repo_slug,
                token=self.github_token,
                base_branch=self.github_base_branch,
            )
        return None

    def _write_report(self, report: PerfReport) -> None:
        out = self.repo_root / ".security_workdir" / "perf_report.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")
        log.info("efficiency_brain: report -> %s", out)
