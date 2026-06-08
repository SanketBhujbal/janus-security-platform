"""Perf scanner — runs Semgrep with our efficiency rules and maps the matches
to PerfFinding objects. Sibling of SemgrepScanner (security mode)."""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from ..models.perf import LANG_BY_EXT, PerfCategory, PerfFinding
from ..models.vulnerability import CodeLocation, Severity
from .semgrep_scanner import DEFAULT_EXCLUDES, SEMGREP_SEVERITY_MAP


log = logging.getLogger("security_brain.perf_scanner")


RULE_TO_CATEGORY = {
    # Python rules (any language) -- check by suffix so the same key matches
    # python / dotnet / java variants when they share a category.
    "nested-loop-same-iterable":     PerfCategory.NESTED_LOOP_SAME_ITERABLE,
    "nested-loop-same-collection":   PerfCategory.NESTED_LOOP_SAME_ITERABLE,
    "linear-search-in-loop":         PerfCategory.LINEAR_SEARCH_IN_LOOP,
    "string-concat-in-loop":         PerfCategory.STRING_CONCAT_IN_LOOP,
    "regex-recompile-in-loop":       PerfCategory.REGEX_RECOMPILE_IN_LOOP,
    "repeated-sort-in-loop":         PerfCategory.REPEATED_SORT_IN_LOOP,
    # .NET specific
    "linq-count-vs-any":             PerfCategory.LINQ_INEFFICIENT,
    "tolist-before-filter":          PerfCategory.LINQ_INEFFICIENT,
    # Java specific
    "boxing-in-arithmetic-loop":     PerfCategory.BOXING_IN_LOOP,
}


class PerfScanner:
    def __init__(self, rules_dir: Path, excludes: Iterable[str] | None = None):
        if shutil.which("semgrep") is None:
            raise RuntimeError("semgrep not found in PATH. pip install semgrep")
        self.rules_dir = rules_dir
        if excludes is None:
            extras = os.environ.get("SEMGREP_EXTRA_EXCLUDES", "").strip()
            extra = [e.strip() for e in extras.split(",") if e.strip()] if extras else []
            self.excludes = list(DEFAULT_EXCLUDES) + extra
        else:
            self.excludes = list(excludes)

    def scan(self, target: Path) -> list[PerfFinding]:
        return self.scan_paths([target])

    def scan_paths(self, targets: Iterable[Path]) -> list[PerfFinding]:
        targets = [t for t in targets]
        if not targets:
            return []
        cmd = [
            "semgrep",
            "--json", "--quiet",
            "--metrics", "off",
            "--disable-version-check",
            "--config", str(self.rules_dir),
        ]
        for ex in self.excludes:
            cmd.extend(["--exclude", ex])
        for t in targets:
            cmd.append(str(t))

        # encoding="utf-8" is required on Windows: our rule messages contain
        # Unicode (e.g. "O(n²)") that cp1252 cannot decode.
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False,
            encoding="utf-8", errors="replace",
        )
        if not result.stdout:
            log.warning(
                "semgrep produced no JSON output (rc=%d). stderr tail:\n%s",
                result.returncode, "\n".join(result.stderr.splitlines()[-5:]),
            )
            return []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            log.error("semgrep returned non-JSON output: %s", e)
            return []
        for err in data.get("errors", []):
            log.warning("semgrep rule error: %s", err.get("message", "")[:200])
        return [self._to_finding(r) for r in data.get("results", [])]

    def _to_finding(self, r: dict) -> PerfFinding:
        rule_id = r.get("check_id", "")
        raw_sev = r.get("severity") or r.get("extra", {}).get("severity", "WARNING")
        severity = SEMGREP_SEVERITY_MAP.get(raw_sev, Severity.MEDIUM)
        file_path = Path(r["path"])
        start_line = r["start"]["line"]
        end_line = r["end"]["line"]
        snippet = self._read_snippet(file_path, start_line, end_line)
        loc = CodeLocation(
            file=file_path, start_line=start_line, end_line=end_line, snippet=snippet,
        )
        category = self._infer_category(rule_id)
        title = r.get("extra", {}).get("message", rule_id).strip().splitlines()[0]
        language = LANG_BY_EXT.get(file_path.suffix.lower(), "python")
        return PerfFinding(
            category=category,
            severity=severity,
            title=title[:120],
            description=r.get("extra", {}).get("message", ""),
            location=loc,
            function_name=self._find_enclosing_function(file_path, start_line, language) or "",
            rule_id=rule_id,
            language=language,
        )

    @staticmethod
    def _infer_category(rule_id: str) -> PerfCategory:
        for key, cat in RULE_TO_CATEGORY.items():
            if key in rule_id:
                return cat
        return PerfCategory.OTHER

    @staticmethod
    def _read_snippet(file: Path, start: int, end: int, context: int = 1) -> str:
        try:
            lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        if not lines:
            return ""
        lo = max(0, start - 1 - context)
        hi = min(len(lines), end + context)
        return "\n".join(lines[lo:hi])

    # Matches a Java / C# method declaration and captures the method name:
    #   public static List<Integer> findCommonAccountIds(List<Integer> a, ...)
    _METHOD_RE = re.compile(
        r"^\s*(?:public|private|protected|internal|static|final|virtual|override|async|\s)+"
        r"[\w<>\[\],.\?]+\s+([A-Za-z_]\w*)\s*\(")

    @staticmethod
    def _find_enclosing_function(file: Path, line: int, language: str = "python") -> str | None:
        # Walk backwards from `line` until we hit a function/method declaration.
        # Cheap heuristic, good enough for the refactor agent's prompt context.
        try:
            text = file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None
        for i in range(min(line - 1, len(text) - 1), -1, -1):
            stripped = text[i].lstrip()
            if language == "python":
                if stripped.startswith("def ") and "(" in stripped:
                    return stripped[len("def "):].split("(", 1)[0].strip()
            else:
                m = PerfScanner._METHOD_RE.match(text[i])
                if m and m.group(1) not in ("if", "for", "while", "switch", "catch", "return"):
                    return m.group(1)
        return None
