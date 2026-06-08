from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from ..models.vulnerability import (
    CodeLocation,
    Severity,
    VulnCategory,
    Vulnerability,
)


log = logging.getLogger("security_brain.scanner")


SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


# Files / directories excluded by default. The dominant noise on a real
# .NET / MVC repo is third-party JS shipped in `Scripts/` and `Content/`
# (jquery, modernizr, bootstrap, respond, etc.) -- thousands of lines of
# minified code that match generic XSS / innerHTML patterns and that the
# customer can't and won't fix anyway. Exclude them at the source.
#
# We use filename globs (not full path) for vendor libs so they're caught
# regardless of which directory hosts them. Build / dep directories are
# excluded by directory name.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    # .NET / generic build outputs and dependency stores
    "bin", "obj", "packages", "TestResults", "coverage",
    ".git", ".vs", ".idea", ".gradle", ".next",
    # JS / Node dep stores
    "node_modules", "bower_components", "vendor",
    # Modern .NET MVC client-side lib location
    "wwwroot/lib",
    # Minified / bundled assets (never your own source)
    "*.min.js", "*.min.css", "*.bundle.js", "*.bundle.css",
    "*-min.js", "*.map",
    # Common third-party JS libraries that ship inside .NET MVC Scripts/ + Content/
    "jquery*.js", "jquery-*.js", "jquery.*.js",
    "modernizr*.js", "modernizr-*.js",
    "bootstrap*.js", "bootstrap-*.js", "bootstrap-slider*.js",
    "respond*.js", "respond-*.js",
    "popper*.js", "lodash*.js", "moment*.js", "underscore*.js",
    "knockout*.js", "ember*.js", "backbone*.js",
    "react*.js", "vue*.js", "angular-*.js",
    "core-js*.js", "polyfills*.js",
    "vendor*.js", "*-vendor*.js", "*.vendor.js",
    # TypeScript declaration files (no executable code)
    "*.d.ts",
    # Auto-generated .NET code: SOAP/WSDL proxy stubs, ResX designer, EF model
    # snapshot, T4 templates, etc. These contain identifier text like
    # `CardNumber` purely because the source schema does -- never customer code.
    "Reference.cs",
    "*.g.cs",
    "*.g.i.cs",
    "*.Designer.cs",
    "*.designer.cs",
    "*.generated.cs",
    "*.Generated.cs",
    "TemporaryGeneratedFile_*.cs",
    "AssemblyInfo.cs",        # one-line attribute file, never has security code
    "GlobalAssemblyInfo.cs",
)

RULE_CATEGORY_MAP = {
    "missing-idempotency":       VulnCategory.MISSING_IDEMPOTENCY,
    "amount-tampering":          VulnCategory.AMOUNT_TAMPERING,
    "pan-cvv-logging":           VulnCategory.SENSITIVE_LOGGING,
    "weak-payment-validation":   VulnCategory.WEAK_PAYMENT_VALIDATION,
    "duplicate-payment":         VulnCategory.DUPLICATE_PAYMENT,
    "broken-authz":              VulnCategory.BROKEN_AUTHZ,
    "session-misuse":            VulnCategory.SESSION_MISUSE,
    "sql-injection":             VulnCategory.SQL_INJECTION,
    "ef-raw-sql":                VulnCategory.SQL_INJECTION,
    "webhook-amount-trust":      VulnCategory.AMOUNT_TAMPERING,
    "weak-jwt":                  VulnCategory.BROKEN_AUTH,
    "card-data-in":              VulnCategory.SENSITIVE_LOGGING,
    "auth-token-in":             VulnCategory.SESSION_MISUSE,
    "bypass-security-trust":     VulnCategory.XSS,
    "inner-html":                VulnCategory.XSS,
    "console-log-card":          VulnCategory.SENSITIVE_LOGGING,
    "client-amount":             VulnCategory.AMOUNT_TAMPERING,
    "connection-string":         VulnCategory.OTHER,
    "api-key":                   VulnCategory.OTHER,
    # Java-specific rules
    "hibernate-hql-injection":             VulnCategory.SQL_INJECTION,
    "hardcoded-db-password":               VulnCategory.OTHER,
    "hardcoded-api-key":                   VulnCategory.OTHER,
    # Weak cryptography (all languages)
    "weak-hash-algorithm":                 VulnCategory.INSECURE_CRYPTO,
    "weak-cipher-algorithm":               VulnCategory.INSECURE_CRYPTO,
    "insecure-random":                     VulnCategory.INSECURE_CRYPTO,
    # XXE (Java + .NET)
    "xxe-documentbuilder":                 VulnCategory.XXE,
    "xxe-saxparser":                       VulnCategory.XXE,
    "xxe-xmlinputfactory":                 VulnCategory.XXE,
    "xxe-xmldocument":                     VulnCategory.XXE,
    "xxe-xmltextreader":                   VulnCategory.XXE,
    "xxe-xmlreader-no-settings":           VulnCategory.XXE,
    # Insecure deserialization (Java + .NET)
    "insecure-deserialization-objectinputstream": VulnCategory.INSECURE_DESERIALIZATION,
    "insecure-deserialization-xstream":    VulnCategory.INSECURE_DESERIALIZATION,
    "binaryformatter-deserialization":     VulnCategory.INSECURE_DESERIALIZATION,
    "json-typehandling-all":               VulnCategory.INSECURE_DESERIALIZATION,
    "losformatter-deserialization":        VulnCategory.INSECURE_DESERIALIZATION,
    # Spring Security misconfiguration
    "spring-security-csrf-disabled":       VulnCategory.BROKEN_AUTH,
    "spring-security-permit-all-requests": VulnCategory.BROKEN_AUTHZ,
    "spring-security-frame-options-disabled": VulnCategory.OTHER,
    "spring-security-headers-disabled":    VulnCategory.OTHER,
    # SSRF
    "ssrf-requests-user-url":             VulnCategory.SSRF,
    "ssrf-urllib-user-url":               VulnCategory.SSRF,
    # Command injection
    "command-injection-runtime":          VulnCategory.COMMAND_INJECTION,
    "command-injection-processbuilder":   VulnCategory.COMMAND_INJECTION,
    "command-injection-process-start":    VulnCategory.COMMAND_INJECTION,
    "command-injection-subprocess":       VulnCategory.COMMAND_INJECTION,
    # Path traversal
    "path-traversal-file":                VulnCategory.PATH_TRAVERSAL,
    "path-traversal-resource":            VulnCategory.PATH_TRAVERSAL,
    "path-traversal-file-read":           VulnCategory.PATH_TRAVERSAL,
    "path-traversal-path-combine":        VulnCategory.PATH_TRAVERSAL,
    "path-traversal-open":                VulnCategory.PATH_TRAVERSAL,
    # Open redirect
    "open-redirect":                      VulnCategory.OPEN_REDIRECT,
    "open-redirect-router":               VulnCategory.OPEN_REDIRECT,
    # Insecure TLS
    "tls-cert-validation-disabled":       VulnCategory.INSECURE_TLS,
    "tls-old-protocol":                   VulnCategory.INSECURE_TLS,
    # CORS misconfiguration
    "cors-allow-all-origins":             VulnCategory.CORS_MISCONFIG,
    "cors-credentials-with-wildcard":     VulnCategory.CORS_MISCONFIG,
    "cors-allow-any-origin":              VulnCategory.CORS_MISCONFIG,
    # Log4j JNDI / injection
    "log4j-jndi-injection":               VulnCategory.COMMAND_INJECTION,
    # Race condition / double-spend
    "double-spend-non-atomic-balance":    VulnCategory.RACE_CONDITION,
    "missing-transactional-on-payment":   VulnCategory.RACE_CONDITION,
    # Insecure cookie flags
    "cookie-missing-secure-flag":         VulnCategory.INSECURE_COOKIE,
    "cookie-missing-httponly-flag":       VulnCategory.INSECURE_COOKIE,
    "cookie-missing-secure-httponly":     VulnCategory.INSECURE_COOKIE,
    # Timing attacks
    "timing-attack-string-compare":       VulnCategory.TIMING_ATTACK,
    "timing-attack-hmac-verify":          VulnCategory.TIMING_ATTACK,
}


class SemgrepScanner:
    # `extra_configs` defaults to empty: the bundled rules are what makes this
    # tool valuable, and pulling `--config auto` requires reaching semgrep.dev,
    # which fails behind corporate TLS-inspecting proxies (common in enterprise).
    # Opt in via env var SEMGREP_EXTRA_CONFIGS="auto,p/security-audit" or by
    # passing extra_configs explicitly.
    def __init__(
        self,
        rules_dir: Path | Iterable[Path],
        extra_configs: Iterable[str] | None = None,
        excludes: Iterable[str] | None = None,
    ):
        if shutil.which("semgrep") is None:
            raise RuntimeError("semgrep not found in PATH. Install with: pip install semgrep")
        # Accept either a single Path (back-compat) or an iterable of Paths.
        if isinstance(rules_dir, Path):
            self.rules_dirs: list[Path] = [rules_dir]
        else:
            self.rules_dirs = list(rules_dir)
        # Keep .rules_dir for back-compat (tests + CLI argparse).
        self.rules_dir = self.rules_dirs[0]
        if extra_configs is None:
            env = os.environ.get("SEMGREP_EXTRA_CONFIGS", "").strip()
            extra_configs = [c.strip() for c in env.split(",") if c.strip()] if env else []
        self.extra_configs = list(extra_configs)
        # Excludes: caller can override entirely, otherwise the bundled
        # DEFAULT_EXCLUDES (vendor JS + build dirs) plus any extras from
        # SEMGREP_EXTRA_EXCLUDES env var.
        if excludes is None:
            extras = os.environ.get("SEMGREP_EXTRA_EXCLUDES", "").strip()
            extra_excludes = [e.strip() for e in extras.split(",") if e.strip()] if extras else []
            self.excludes = list(DEFAULT_EXCLUDES) + extra_excludes
        else:
            self.excludes = list(excludes)

    def scan(self, target: Path) -> list[Vulnerability]:
        # Privacy: --metrics off disables semgrep's anonymized telemetry to
        # metrics.semgrep.dev (rule IDs / timings / errors -- NOT file content,
        # but better explicit-off). --disable-version-check stops the
        # version ping. Source code never leaves the host either way.
        cmd = [
            "semgrep",
            "--json", "--quiet",
            "--metrics", "off",
            "--disable-version-check",
        ]
        for r in self.rules_dirs:
            cmd.extend(["--config", str(r)])
        for cfg in self.extra_configs:
            cmd.extend(["--config", cfg])
        for ex in self.excludes:
            cmd.extend(["--exclude", ex])
        cmd.append(str(target))

        # encoding="utf-8" is required on Windows: cp1252 (the default) can't
        # decode Unicode like "O(n²)" or "CO₂" that may appear in rule messages.
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
        return [self._to_vuln(r) for r in data.get("results", [])]

    def _to_vuln(self, r: dict) -> Vulnerability:
        rule_id = r.get("check_id", "")
        # Newer semgrep puts severity under r["extra"]; older puts it top-level.
        raw_sev = r.get("severity") or r.get("extra", {}).get("severity", "WARNING")
        severity = SEMGREP_SEVERITY_MAP.get(raw_sev, Severity.MEDIUM)
        metadata = r.get("extra", {}).get("metadata", {})
        category = self._infer_category(rule_id, metadata)
        file_path = Path(r["path"])
        start_line = r["start"]["line"]
        end_line = r["end"]["line"]
        snippet = self._read_snippet(file_path, start_line, end_line)
        loc = CodeLocation(
            file=file_path,
            start_line=start_line,
            end_line=end_line,
            snippet=snippet,
        )
        return Vulnerability(
            category=category,
            severity=severity,
            title=r.get("extra", {}).get("message", rule_id),
            description=r.get("extra", {}).get("message", ""),
            location=loc,
            rule_id=rule_id,
        )

    @staticmethod
    def _read_snippet(file: Path, start: int, end: int, context: int = 1) -> str:
        # OSS semgrep replaces matched lines with "requires login" unless you
        # auth against semgrep.dev. We read straight from disk to bypass that.
        # A few lines of context on each side make the snippet self-explanatory.
        try:
            lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
        except (OSError, ValueError):
            return ""
        if not lines:
            return ""
        lo = max(0, start - 1 - context)
        hi = min(len(lines), end + context)
        return "\n".join(lines[lo:hi])

    def _infer_category(self, rule_id: str, metadata: dict) -> VulnCategory:
        for key, cat in RULE_CATEGORY_MAP.items():
            if key in rule_id:
                return cat
        cwe_field = metadata.get("cwe", "")
        cwe = " ".join(cwe_field) if isinstance(cwe_field, list) else str(cwe_field)
        if "89" in cwe:
            return VulnCategory.SQL_INJECTION
        if "79" in cwe:
            return VulnCategory.XSS
        if "287" in cwe:
            return VulnCategory.BROKEN_AUTH
        if "285" in cwe:
            return VulnCategory.BROKEN_AUTHZ
        if "532" in cwe:
            return VulnCategory.SENSITIVE_LOGGING
        return VulnCategory.OTHER
