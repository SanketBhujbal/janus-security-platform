"""CI guard mode (P5).

Efficiency is otherwise a one-shot "go optimize this repo" tool. CI guard turns
it into a continuous gate: scan only the files a PR changed, report efficiency
anti-patterns inline, and (optionally) fail the build when a HIGH+ severity
pattern is *introduced*. This is how the product becomes part of the daily
workflow instead of a demo button.

It reuses PerfScanner (no LLM, no benchmark) and emits the same event protocol
as the brains so the existing SSE UI renders it for free.
"""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .events import (
    EventCallback,
    FINDING_DISCOVERED,
    SCAN_DONE,
    SCAN_FINDINGS_PRIORITIZED,
    SCAN_FINDINGS_RAW,
    SCAN_START,
    noop_emitter,
)
from .models.perf import PerfFinding
from .models.vulnerability import Severity
from .scanners.perf_scanner import PerfScanner

log = logging.getLogger("efficiency_brain.ci_guard")

CI_VERDICT = "ci_verdict"

_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


@dataclass
class CIGuardReport:
    base_ref: str = ""
    changed_files: list[str] = field(default_factory=list)
    findings: list[PerfFinding] = field(default_factory=list)
    fail_severity: Severity = Severity.HIGH
    passed: bool = True

    @property
    def scanned(self) -> int:
        # ScanManager.list() reads `report.scanned`; mirror PerfReport's field.
        return len(self.findings)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity.value] = out.get(f.severity.value, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "mode": "efficiency-ci-guard",
            "base_ref": self.base_ref,
            "changed_files": self.changed_files,
            "scanned": len(self.findings),
            "passed": self.passed,
            "fail_severity": self.fail_severity.value,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
        }


class CIGuard:
    def __init__(
        self,
        repo_root: Path,
        rules_dir: Path,
        base_ref: str = "origin/main",
        fail_severity: Severity = Severity.HIGH,
        max_findings: int = 100,
        on_event: EventCallback | None = None,
        github_repo_slug: str | None = None,
        github_token: str | None = None,
        pr_number: int | None = None,
    ):
        self.repo_root = Path(repo_root).resolve()
        self.scanner = PerfScanner(rules_dir=rules_dir)
        self.base_ref = base_ref
        self.fail_severity = fail_severity
        self.max_findings = max_findings
        self._emit_raw = on_event or noop_emitter
        self.github_repo_slug = github_repo_slug
        self.github_token = github_token
        self.pr_number = pr_number

    def _emit(self, type: str, message: str, **data) -> None:
        try:
            self._emit_raw(type, message, **data)
        except Exception:
            log.exception("ci_guard event emit failed")

    # ------------------------------------------------------------------
    def changed_files(self) -> list[Path]:
        """Files changed vs. base_ref (added/modified). Falls back to the working
        tree diff if the ref isn't resolvable (e.g. shallow CI checkout)."""
        for args in (
            ["git", "diff", "--name-only", "--diff-filter=d", f"{self.base_ref}...HEAD"],
            ["git", "diff", "--name-only", "--diff-filter=d", self.base_ref],
            ["git", "diff", "--name-only", "--diff-filter=d", "HEAD"],
        ):
            try:
                r = subprocess.run(
                    args, cwd=self.repo_root, capture_output=True, text=True,
                    timeout=30, encoding="utf-8", errors="replace")
            except (subprocess.TimeoutExpired, OSError):
                continue
            if r.returncode == 0:
                names = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
                paths = [(self.repo_root / n) for n in names]
                paths = [p for p in paths if p.exists() and p.suffix.lower() in (".py", ".java", ".cs")]
                if paths or r.returncode == 0:
                    return paths
        return []

    def run(self) -> CIGuardReport:
        report = CIGuardReport(base_ref=self.base_ref, fail_severity=self.fail_severity)
        self._emit(SCAN_START, f"CI guard: diffing against {self.base_ref}",
                   repo=str(self.repo_root), mode="efficiency-ci-guard")

        changed = self.changed_files()
        report.changed_files = [str(p.relative_to(self.repo_root)) if p.is_relative_to(self.repo_root)
                                else str(p) for p in changed]
        if not changed:
            self._emit(SCAN_FINDINGS_RAW, "no changed source files to scan", count=0)
            self._emit(CI_VERDICT, "PASS — no changed source files", passed=True, counts={})
            self._emit(SCAN_DONE, "ci guard finished", summary=report.to_dict())
            return report

        raw = self.scanner.scan_paths(changed)
        self._emit(SCAN_FINDINGS_RAW,
                   f"scanned {len(changed)} changed file(s); {len(raw)} finding(s)",
                   count=len(raw))

        prioritized = sorted(raw, key=lambda f: _SEV_ORDER.index(f.severity), reverse=True)
        prioritized = prioritized[: self.max_findings]
        report.findings = prioritized
        self._emit(SCAN_FINDINGS_PRIORITIZED,
                   f"{len(prioritized)} finding(s) in the diff", count=len(prioritized))

        threshold = _SEV_ORDER.index(self.fail_severity)
        for idx, f in enumerate(prioritized):
            blocking = _SEV_ORDER.index(f.severity) >= threshold
            if blocking:
                report.passed = False
            self._emit(
                FINDING_DISCOVERED,
                f"{f.category.value} @ {f.location.as_pointer()}",
                idx=idx,
                category=f.category.value,
                severity=f.severity.value,
                location=f.location.as_pointer(),
                rule_id=f.rule_id or "",
                title=f.title,
                function_name=f.function_name,
                language=f.language,
                fingerprint=f.fingerprint,
                blocking=blocking,
                status=f.status.value,
            )

        verdict = "PASS" if report.passed else "FAIL"
        self._emit(
            CI_VERDICT,
            f"{verdict} — {len(prioritized)} finding(s), "
            f"fail threshold = {self.fail_severity.value}",
            passed=report.passed, counts=report.counts(),
        )
        self._maybe_comment_on_pr(report)
        self._emit(SCAN_DONE, "ci guard finished", summary=report.to_dict())
        return report

    # ------------------------------------------------------------------
    def _maybe_comment_on_pr(self, report: CIGuardReport) -> None:
        if not (self.github_repo_slug and self.pr_number):
            return
        try:
            body = self._render_comment(report)
            from github import Github
            try:
                from github import Auth as GithubAuth
                gh = Github(auth=GithubAuth.Token(
                    self.github_token), verify=False)  # type: ignore[arg-type]
            except (ImportError, TypeError):
                gh = Github(self.github_token, verify=False)
            repo = gh.get_repo(self.github_repo_slug)
            repo.get_issue(self.pr_number).create_comment(body)
            log.info("ci_guard: posted comment on PR #%d", self.pr_number)
        except Exception as e:
            log.warning("ci_guard: could not post PR comment: %s", e)

    @staticmethod
    def _render_comment(report: CIGuardReport) -> str:
        verdict = "✅ PASS" if report.passed else "❌ FAIL"
        lines = [
            f"## JANUS Efficiency CI Guard — {verdict}",
            "",
            f"Scanned {len(report.changed_files)} changed file(s) against "
            f"`{report.base_ref}`. Fail threshold: `{report.fail_severity.value}`.",
            "",
        ]
        if not report.findings:
            lines.append("No efficiency anti-patterns introduced. 🎉")
            return "\n".join(lines)
        lines.append("| Severity | Category | Location | Function |")
        lines.append("|----------|----------|----------|----------|")
        for f in report.findings:
            lines.append(
                f"| `{f.severity.value}` | `{f.category.value}` | "
                f"`{f.location.as_pointer()}` | `{f.function_name or '-'}` |")
        return "\n".join(lines)
