from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from orchestrator.models.vulnerability import (
    CodeLocation,
    Severity,
    VulnCategory,
    Vulnerability,
)
from orchestrator.orchestrator import SecurityBrain


def _vuln(repo: Path, cat: VulnCategory, sev: Severity, line: int = 10) -> Vulnerability:
    return Vulnerability(
        category=cat,
        severity=sev,
        title=f"{cat.value}",
        description="d",
        location=CodeLocation(file=repo / "x.py", start_line=line, end_line=line + 1),
        rule_id=f"rule.{cat.value}",
    )


def test_scan_only_skips_attacker_and_writes_report(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "x.py").write_text("ok = True\n", encoding="utf-8")

    rules = tmp_path / "rules"
    rules.mkdir()

    canned = [
        _vuln(repo, VulnCategory.SQL_INJECTION, Severity.HIGH, line=10),
        _vuln(repo, VulnCategory.AMOUNT_TAMPERING, Severity.MEDIUM, line=20),
        _vuln(repo, VulnCategory.SENSITIVE_LOGGING, Severity.LOW, line=30),
    ]
    # Don't require semgrep binary or run subprocess.
    with patch("orchestrator.scanners.semgrep_scanner.shutil.which", return_value="/fake/semgrep"):
        brain = SecurityBrain(
            repo_root=repo,
            target_endpoint=None,
            rules_dir=rules,
            min_severity=Severity.MEDIUM,
            scan_only=True,
        )
    brain.scanner.scan = lambda _root: canned  # type: ignore[method-assign]

    report = brain.run_security_loop()

    assert report.mode == "scan-only"
    # LOW is filtered out by min-severity=MEDIUM
    assert report.scanned == 2
    assert report.exploited == report.patched == report.validated == report.failed == 0
    assert {v.category for v in report.vulnerabilities} == {
        VulnCategory.SQL_INJECTION, VulnCategory.AMOUNT_TAMPERING
    }

    report_path = repo / ".security_workdir" / "report.json"
    assert report_path.exists()
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["mode"] == "scan-only"
    assert len(payload["findings"]) == 2


def test_scan_only_skips_findings_already_validated(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "x.py").write_text("ok = True\n", encoding="utf-8")
    rules = tmp_path / "rules"
    rules.mkdir()

    v = _vuln(repo, VulnCategory.SQL_INJECTION, Severity.HIGH)

    with patch("orchestrator.scanners.semgrep_scanner.shutil.which", return_value="/fake/semgrep"):
        # First run records it as validated by hand.
        b1 = SecurityBrain(repo_root=repo, target_endpoint=None, rules_dir=rules, scan_only=True)
    b1.scanner.scan = lambda _root: [v]  # type: ignore[method-assign]
    # Manually mark validated and save to simulate a prior successful run.
    from orchestrator.models.vulnerability import FindingStatus
    v.status = FindingStatus.VALIDATED
    b1.history.record(v)
    b1.history.save()

    # Second run: same fingerprint, should be skipped.
    fresh = _vuln(repo, VulnCategory.SQL_INJECTION, Severity.HIGH)  # same location/category
    assert fresh.fingerprint == v.fingerprint
    with patch("orchestrator.scanners.semgrep_scanner.shutil.which", return_value="/fake/semgrep"):
        b2 = SecurityBrain(repo_root=repo, target_endpoint=None, rules_dir=rules, scan_only=True)
    b2.scanner.scan = lambda _root: [fresh]  # type: ignore[method-assign]
    report = b2.run_security_loop()

    assert report.skipped_already_fixed == 1
    assert report.scanned == 1
