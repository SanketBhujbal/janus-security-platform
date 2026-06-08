"""Scan an arbitrary repository for security findings.

This is the entry point to use on a real product repo. It runs the same
Semgrep + payments-rules pipeline as the full Brain loop, but stops after
the findings stage -- no exploit execution, no LLM calls, no Docker, no
API key required. Output is a prioritized table + a JSON report.

Usage:
    python -m scripts.scan --repo <path-to-your-repo>
    python -m scripts.scan --repo C:\\path\\to\\product --min-severity high
    python -m scripts.scan --repo C:\\path\\to\\product --rules-extra C:\\custom-rules

Multi-language: Semgrep's `--config auto` (used by default) covers Python,
Java, JS/TS, Go, Ruby, PHP, C#, etc. The bundled payments rules are
Python-specific but the auto config catches generic SQLi, XSS, hardcoded
secrets, etc. across all supported languages.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orchestrator.models.vulnerability import Severity
from orchestrator.orchestrator import SecurityBrain


DEFAULT_RULES = ROOT / "orchestrator" / "rules" / "payments"


class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"


SEVERITY_COLOR = {
    "critical": C.RED + C.BOLD,
    "high": C.RED,
    "medium": C.YELLOW,
    "low": C.CYAN,
    "info": C.DIM,
}


def main() -> int:
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--repo", required=True, type=Path, help="path to the repository to scan")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES,
                        help="primary Semgrep rules dir (default: bundled payments rules)")
    parser.add_argument("--min-severity", default="medium",
                        choices=[s.value for s in Severity])
    parser.add_argument("--max-findings", type=int, default=200,
                        help="cap on findings to include in the report")
    parser.add_argument("--report", type=Path, default=None,
                        help="where to write report.json (default: <repo>/.security_workdir/report.json)")
    parser.add_argument("--history", type=Path, default=None,
                        help="path to history.json (default: <repo>/.security_workdir/history.json)")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    if not args.repo.exists():
        print(f"[fail] --repo path does not exist: {args.repo}", file=sys.stderr)
        return 2
    if not args.rules.exists():
        print(f"[fail] --rules path does not exist: {args.rules}", file=sys.stderr)
        return 2

    if args.no_color:
        for attr in list(vars(C)):
            if not attr.startswith("_"):
                setattr(C, attr, "")

    try:
        brain = SecurityBrain(
            repo_root=args.repo,
            target_endpoint=None,
            rules_dir=args.rules,
            min_severity=Severity(args.min_severity),
            max_findings_per_run=args.max_findings,
            scan_only=True,
            history_path=args.history,
        )
    except RuntimeError as e:
        print(f"{C.RED}[fail]{C.END} {e}", file=sys.stderr)
        print(f"{C.DIM}install dependencies first: pip install -r requirements.txt{C.END}", file=sys.stderr)
        return 2

    print(f"{C.BOLD}{C.CYAN}scanning {args.repo}{C.END}")
    print(f"{C.DIM}  rules:        {args.rules}{C.END}")
    print(f"{C.DIM}  min-severity: {args.min_severity}{C.END}")
    report = brain.run_security_loop()

    _print_findings(report.vulnerabilities)
    _print_summary(report)

    report_path = args.report or (args.repo / ".security_workdir" / "report.json")
    print(f"\n{C.DIM}full report: {report_path}{C.END}")
    return 0


def _print_findings(vulns: list) -> None:
    if not vulns:
        print(f"\n{C.GREEN}no findings at the requested severity threshold.{C.END}")
        return
    print(f"\n{C.BOLD}findings ({len(vulns)}):{C.END}")
    for v in vulns:
        sev = SEVERITY_COLOR.get(v.severity.value, "") + v.severity.value.upper().ljust(8) + C.END
        cat = f"{C.MAGENTA}{v.category.value:<28}{C.END}"
        loc = f"{C.DIM}{v.location.as_pointer()}{C.END}"
        rule = f"{C.DIM}{v.rule_id or '(no rule id)'}{C.END}"
        title = (v.title or "").splitlines()[0][:80]
        print(f"  {sev} {cat} {loc}")
        print(f"           rule:  {rule}")
        if title:
            print(f"           title: {title}")


def _print_summary(report) -> None:
    by_cat = Counter(v.category.value for v in report.vulnerabilities)
    by_sev = Counter(v.severity.value for v in report.vulnerabilities)
    print(f"\n{C.BOLD}summary{C.END}")
    print(f"  scanned:     {report.scanned}")
    print(f"  skipped:     {report.skipped_already_fixed}  {C.DIM}(validated in earlier run){C.END}")
    if by_sev:
        print("  by severity:")
        for sev in ("critical", "high", "medium", "low", "info"):
            if by_sev.get(sev):
                print(f"    {SEVERITY_COLOR.get(sev,'')}{sev:<8}{C.END}  {by_sev[sev]}")
    if by_cat:
        print("  by category:")
        for cat, n in by_cat.most_common():
            print(f"    {cat:<28} {n}")


if __name__ == "__main__":
    sys.exit(main())
