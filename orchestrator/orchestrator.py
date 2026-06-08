from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .agents.attacker import AttackerAgent
from .agents.base import AgentContext
from .agents.healer import HealerAgent
from .agents.hypothesis import AttackChain, HypothesisAgent
from .agents.validator import ValidatorAgent
from .events import (
    AGENT_DONE,
    AGENT_START,
    CHAINS_DISCOVERED,
    EventCallback,
    FINDING_COMPLETED,
    FINDING_DISCOVERED,
    FINDING_SKIPPED,
    PR_OPENED,
    SCAN_DONE,
    SCAN_FINDINGS_PRIORITIZED,
    SCAN_FINDINGS_RAW,
    SCAN_START,
    noop_emitter,
)
from .exploits.runner import SandboxRunner
from .llm.claude_client import ClaudeClient, LLMClient
from .models.vulnerability import FindingStatus, Severity, Vulnerability
from .sandbox.target_deployer import (
    ComposeTargetDeployer,
    NullTargetDeployer,
    TargetDeployer,
)
from .scanners.semgrep_scanner import SemgrepScanner
from .state.history import FindingHistory


log = logging.getLogger("security_brain")


@dataclass
class LoopReport:
    scanned: int = 0
    skipped_already_fixed: int = 0
    exploited: int = 0
    patched: int = 0
    validated: int = 0
    failed: int = 0
    mode: str = "full"
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    chains: list[AttackChain] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "scanned": self.scanned,
            "skipped_already_fixed": self.skipped_already_fixed,
            "exploited": self.exploited,
            "patched": self.patched,
            "validated": self.validated,
            "failed": self.failed,
            "chains": [c.to_dict() for c in self.chains],
            "findings": [v.to_dict() for v in self.vulnerabilities],
        }


class SecurityBrain:
    # Coordinator: owns the scan -> exploit -> patch -> validate -> PR loop.

    def __init__(
        self,
        repo_root: Path,
        target_endpoint: str | None,
        rules_dir: Path,
        llm: LLMClient | None = None,
        min_severity: Severity = Severity.MEDIUM,
        max_findings_per_run: int = 25,
        deployer: TargetDeployer | None = None,
        scan_only: bool = False,
        history_path: Path | None = None,
        on_event: EventCallback | None = None,
        runner: object | None = None,
        test_command: list[str] | None = None,
        github_repo_slug: str | None = None,
        github_token: str | None = None,
        github_base_branch: str = "main",
    ):
        self.repo_root = repo_root.resolve()
        self.target_endpoint = target_endpoint
        self.scanner = SemgrepScanner(rules_dir=rules_dir)
        self.github_repo_slug = github_repo_slug
        self.github_token = github_token
        self.github_base_branch = github_base_branch
        self.min_severity = min_severity
        self.max_findings_per_run = max_findings_per_run
        self.scan_only = scan_only
        self._emit_raw = on_event or noop_emitter
        self.history = FindingHistory(
            history_path or (self.repo_root / ".security_workdir" / "history.json")
        )
        # In scan-only mode we don't need LLM / sandbox / deployer, so don't
        # construct them — that means users can run scans without setting
        # ANTHROPIC_API_KEY or installing Docker.
        if scan_only:
            self.llm = None
            self.sandbox = None
            self.deployer = NullTargetDeployer()
            self.attacker = None
            self.healer = None
            self.validator = None
        else:
            self.llm = llm or ClaudeClient()
            # Caller can inject a SubprocessRunner (no Docker) instead of the
            # default SandboxRunner. Lazy-construct SandboxRunner so a missing
            # `docker` binary doesn't blow up scan-only or subprocess-mode runs.
            self.sandbox = runner if runner is not None else SandboxRunner()
            self.deployer = deployer or NullTargetDeployer()
            self.attacker = AttackerAgent(self.llm, self.sandbox)
            self.healer = HealerAgent(self.llm)
            self.hypothesis = HypothesisAgent(self.llm)
            self.validator = ValidatorAgent(
                self.llm, self.sandbox, test_command=test_command, deployer=self.deployer
            )

    def _emit(self, type: str, message: str, **data) -> None:
        try:
            self._emit_raw(type, message, **data)
        except Exception:
            log.exception("event emit failed (continuing)")

    def run_security_loop(
        self,
        imported_findings: list[Vulnerability] | None = None,
        mode_label: str | None = None,
    ) -> LoopReport:
        # mode_label override lets the caller mark the report as "import-sarif"
        # or "import-checkmarx" instead of the generic "full".
        if mode_label:
            label = mode_label
        elif imported_findings is not None:
            label = "import"
        elif self.scan_only:
            label = "scan-only"
        else:
            label = "full"

        report = LoopReport(mode=label)
        ctx = AgentContext(repo_root=self.repo_root, target_endpoint=self.target_endpoint)

        self._emit(
            SCAN_START,
            f"scanning {self.repo_root} (mode={report.mode})",
            repo=str(self.repo_root),
            mode=report.mode,
            min_severity=self.min_severity.value,
        )

        # Full-loop only: bring the target up BEFORE the attacker tries to
        # exploit it. Validator.reload() runs between patch + replay, but the
        # very first exploit needs an already-running target.
        if not self.scan_only and not isinstance(self.deployer, NullTargetDeployer):
            self._emit(AGENT_START, "deployer: starting target service", agent="deployer")
            ok = self.deployer.reload() and self.deployer.wait_ready(timeout_s=30)
            self._emit(
                AGENT_DONE,
                f"deployer: {'target ready' if ok else 'target failed to start'}",
                agent="deployer",
                ok=ok,
            )
            if not ok:
                log.warning(
                    "deployer: target did not become ready; exploit phase will "
                    "likely fail. Findings that don't require a running target "
                    "(e.g. secrets in config) may still be reported."
                )

        if imported_findings is not None:
            raw = imported_findings
            self._emit(
                SCAN_FINDINGS_RAW,
                f"imported {len(raw)} finding(s) from external scanner",
                count=len(raw),
                source="external",
            )
        else:
            raw = self.scanner.scan(self.repo_root)
            self._emit(SCAN_FINDINGS_RAW, f"semgrep returned {len(raw)} candidate(s)", count=len(raw))

        findings = list(self._filter_and_prioritize(raw))
        # Score each finding by HTTP reachability so directly-routed handlers
        # sort first. Failures here are non-fatal — priority falls back to 1.0.
        try:
            from .analyzers.reachability import ReachabilityAnalyzer
            ReachabilityAnalyzer().analyze(findings, self.repo_root)
        except Exception:
            log.debug("security_brain: reachability analysis skipped", exc_info=True)
        # Re-sort after reachability scores are applied.
        findings = sorted(findings, key=lambda v: -v.priority)
        report.scanned = len(findings)
        log.info("security_brain: prioritized=%d mode=%s", report.scanned, report.mode)
        self._emit(
            SCAN_FINDINGS_PRIORITIZED,
            f"prioritized {len(findings)} finding(s) at >= {self.min_severity.value}",
            count=len(findings),
        )

        # Run hypothesis analysis to identify cross-finding attack chains.
        # This runs before the per-finding exploit loop so the chains are visible
        # in events and the report even if some individual exploits fail.
        if not self.scan_only and findings:
            try:
                self._emit(AGENT_START, "hypothesis: analyzing attack chains", agent="hypothesis")
                chains = self.hypothesis.run(findings, ctx)
                report.chains = chains
                self._emit(
                    CHAINS_DISCOVERED,
                    f"hypothesis: identified {len(chains)} attack chain(s)",
                    agent="hypothesis",
                    count=len(chains),
                    chains=[c.to_dict() for c in chains],
                )
            except Exception:
                log.debug("security_brain: hypothesis analysis failed", exc_info=True)
                self._emit(AGENT_DONE, "hypothesis: skipped (error)", agent="hypothesis", ok=False)

        for idx, vuln in enumerate(findings[: self.max_findings_per_run]):
            self._emit(
                FINDING_DISCOVERED,
                f"{vuln.category.value} @ {vuln.location.as_pointer()}",
                idx=idx,
                fingerprint=vuln.fingerprint,
                category=vuln.category.value,
                severity=vuln.severity.value,
                location=vuln.location.as_pointer(),
                rule_id=vuln.rule_id or "",
                title=(vuln.title or "").splitlines()[0],
                status=vuln.status.value,
            )

            if self.history.should_skip(vuln):
                report.skipped_already_fixed += 1
                vuln.notes.append("brain: skipped — already validated in a previous run")
                vuln.status = FindingStatus.VALIDATED
                report.vulnerabilities.append(vuln)
                self._emit(
                    FINDING_SKIPPED,
                    "already validated in a previous run",
                    idx=idx, fingerprint=vuln.fingerprint,
                )
                self._emit(
                    FINDING_COMPLETED, f"finding #{idx}: {vuln.status.value}",
                    idx=idx, status=vuln.status.value, fingerprint=vuln.fingerprint,
                )
                continue

            log.info(
                "security_brain: working on %s @ %s (priority=%.2f)",
                vuln.category.value, vuln.location.as_pointer(), vuln.priority,
            )

            if self.scan_only:
                report.vulnerabilities.append(vuln)
                self.history.record(vuln)
                self._emit(
                    FINDING_COMPLETED, f"finding #{idx}: {vuln.status.value}",
                    idx=idx, status=vuln.status.value, fingerprint=vuln.fingerprint,
                )
                continue

            # Isolate per-finding agent work: any crash inside attacker /
            # healer / validator (e.g. an LLM JSON parse error, sandbox blew
            # up) must NOT take down the whole loop. Mark the finding failed
            # with the error, keep the partial state on it, and move on so the
            # operator at least sees the work that DID complete.
            try:
                self._emit(AGENT_START, "attacker: generating exploit", agent="attacker", idx=idx)
                vuln = self.attacker.run(vuln, ctx)
                self._emit(
                    AGENT_DONE, f"attacker: {vuln.status.value}",
                    agent="attacker", idx=idx, status=vuln.status.value,
                    exploit_succeeded=bool(vuln.exploit and vuln.exploit.succeeded),
                )

                if vuln.status == FindingStatus.EXPLOITED:
                    report.exploited += 1
                    self._emit(AGENT_START, "healer: generating patch", agent="healer", idx=idx)
                    vuln = self.healer.run(vuln, ctx)
                    self._emit(
                        AGENT_DONE, f"healer: {vuln.status.value}",
                        agent="healer", idx=idx, status=vuln.status.value,
                        patched=bool(vuln.patch),
                    )
                    if vuln.status == FindingStatus.PATCHED:
                        report.patched += 1
                        self._emit(AGENT_START, "validator: tests + replay", agent="validator", idx=idx)
                        vuln = self.validator.run(vuln, ctx)
                        self._emit(
                            AGENT_DONE, f"validator: {vuln.status.value}",
                            agent="validator", idx=idx, status=vuln.status.value,
                        )
                        if vuln.status == FindingStatus.VALIDATED:
                            report.validated += 1
                        else:
                            report.failed += 1
                    else:
                        report.failed += 1
            except Exception as e:
                log.exception("security_brain: finding #%d crashed during agent work", idx)
                report.failed += 1
                vuln.status = FindingStatus.FAILED
                vuln.notes.append(f"brain: {type(e).__name__}: {e}")
                self._emit(
                    AGENT_DONE,
                    f"finding #{idx} errored: {type(e).__name__}: {str(e)[:140]}",
                    idx=idx, status=vuln.status.value, error=str(e)[:300],
                )

            report.vulnerabilities.append(vuln)
            self.history.record(vuln)
            self._emit(
                FINDING_COMPLETED, f"finding #{idx}: {vuln.status.value}",
                idx=idx, status=vuln.status.value, fingerprint=vuln.fingerprint,
            )

        # Always persist + emit -- even if half the findings errored.
        self.history.save()
        self._save_exploit_kb(report)
        self._write_report(report)
        self._try_open_pr(report)
        self._emit(SCAN_DONE, "scan finished", summary=report.to_dict())
        return report

    def _try_open_pr(self, report: LoopReport) -> None:
        if not self.github_repo_slug:
            return
        validated = [v for v in report.vulnerabilities if v.status == FindingStatus.VALIDATED]
        if not validated:
            log.info("security_brain: no validated findings — skipping PR")
            return
        try:
            from .git_ops.github_pr import GitHubPRCreator
            creator = GitHubPRCreator(
                repo_slug=self.github_repo_slug,
                token=self.github_token,
                base_branch=self.github_base_branch,
            )
            pr_url = creator.create_pr_from_report(self.repo_root, report.to_dict())
            if pr_url:
                self._emit(PR_OPENED, f"PR opened: {pr_url}", url=pr_url, count=len(validated))
        except Exception as e:
            log.warning("security_brain: PR creation skipped: %s", e)
            self._emit(PR_OPENED, f"PR skipped: {e}", url="", count=0, error=str(e))

    def _filter_and_prioritize(self, findings: Iterable[Vulnerability]) -> Iterable[Vulnerability]:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        threshold = order.index(self.min_severity)
        eligible = [v for v in findings if order.index(v.severity) <= threshold]
        return sorted(eligible, key=lambda v: -v.priority)

    def _save_exploit_kb(self, report: LoopReport) -> None:
        """Persist successful exploit techniques for future runs."""
        try:
            from .state.exploit_kb import ExploitKnowledgeBase
            kb_path = self.repo_root / ".security_workdir" / "exploit_kb.json"
            kb = ExploitKnowledgeBase(kb_path)
            for vuln in report.vulnerabilities:
                kb.learn(vuln)
            kb.save()
        except Exception:
            log.debug("security_brain: exploit KB save skipped", exc_info=True)

    def _write_report(self, report: LoopReport) -> None:
        workdir = self.repo_root / ".security_workdir"
        workdir.mkdir(parents=True, exist_ok=True)
        out = workdir / "report.json"
        report_dict = report.to_dict()
        out.write_text(json.dumps(report_dict, indent=2, default=str), encoding="utf-8")
        log.info("security_brain: report -> %s", out)

        # Generate a compliance HTML report alongside the JSON report.
        try:
            from .report.compliance import ComplianceReporter
            reporter = ComplianceReporter()
            compliance_dict = reporter.generate_dict(report_dict)
            (workdir / "compliance.json").write_text(
                json.dumps(compliance_dict, indent=2, default=str), encoding="utf-8"
            )
            reporter.generate(report_dict, workdir / "compliance_report.html")
            log.info("security_brain: compliance report -> %s", workdir / "compliance_report.html")
        except Exception:
            log.warning("security_brain: compliance report generation failed", exc_info=True)


def main() -> None:
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    parser = argparse.ArgumentParser(description="Run the agentic security loop on a repo.")
    parser.add_argument("--repo", required=True, type=Path, help="Path to source repo to scan")
    parser.add_argument("--target", required=False, default=None,
                        help="Base URL of running target app under test")
    parser.add_argument("--rules", required=True, type=Path,
                        help="Path to Semgrep payments rules directory")
    parser.add_argument("--min-severity", default="medium",
                        choices=[s.value for s in Severity])
    parser.add_argument("--scan-only", action="store_true",
                        help="scan + prioritize only; no LLM, no exploits, no patches")
    parser.add_argument("--history", type=Path, default=None,
                        help="path to history.json (default: <repo>/.security_workdir/history.json)")
    parser.add_argument("--compose-file", type=Path, default=None,
                        help="docker compose file containing the target service "
                             "(enables rebuild-on-patch in the validator)")
    parser.add_argument("--compose-service", default=None,
                        help="compose service name for the target app")
    parser.add_argument("--health-url", default=None,
                        help="URL the deployer polls after rebuild to confirm readiness")
    args = parser.parse_args()

    deployer: TargetDeployer | None = None
    if args.compose_file and args.compose_service:
        deployer = ComposeTargetDeployer(
            compose_file=args.compose_file,
            service=args.compose_service,
            health_url=args.health_url,
        )

    brain = SecurityBrain(
        repo_root=args.repo,
        target_endpoint=args.target,
        rules_dir=args.rules,
        min_severity=Severity(args.min_severity),
        deployer=deployer,
        scan_only=args.scan_only,
        history_path=args.history,
    )
    report = brain.run_security_loop()
    print(json.dumps(report.to_dict(), indent=2, default=str))


if __name__ == "__main__":
    main()
