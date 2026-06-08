"""SARIF 2.1.0 importer.

Converts findings from any SARIF-emitting scanner (Checkmarx, CodeQL, Semgrep
Cloud, Snyk, GitHub Advanced Security, Veracode) into Vulnerability objects
that the SecurityBrain exploit→patch→validate pipeline can process.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from urllib.parse import urlparse, unquote

from ..models.vulnerability import (
    CodeLocation,
    Severity,
    VulnCategory,
    Vulnerability,
)
from ..scanners.semgrep_scanner import RULE_CATEGORY_MAP

log = logging.getLogger("security_brain.sarif_importer")

_SARIF_LEVEL_MAP = {
    "error":   Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note":    Severity.LOW,
    "none":    Severity.INFO,
}

_SARIF_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
    "note":     Severity.INFO,
    "warning":  Severity.MEDIUM,
    "error":    Severity.HIGH,
}

_CWE_CATEGORY_MAP = {
    "89":  VulnCategory.SQL_INJECTION,
    "79":  VulnCategory.XSS,
    "78":  VulnCategory.COMMAND_INJECTION,
    "22":  VulnCategory.PATH_TRAVERSAL,
    "601": VulnCategory.OPEN_REDIRECT,
    "918": VulnCategory.SSRF,
    "611": VulnCategory.XXE,
    "502": VulnCategory.INSECURE_DESERIALIZATION,
    "295": VulnCategory.INSECURE_TLS,
    "287": VulnCategory.BROKEN_AUTH,
    "285": VulnCategory.BROKEN_AUTHZ,
    "327": VulnCategory.INSECURE_CRYPTO,
    "338": VulnCategory.INSECURE_CRYPTO,
    "352": VulnCategory.BROKEN_AUTH,
    "532": VulnCategory.SENSITIVE_LOGGING,
    "362": VulnCategory.RACE_CONDITION,
    "614": VulnCategory.INSECURE_COOKIE,
    "208": VulnCategory.TIMING_ATTACK,
    "798": VulnCategory.OTHER,
    "942": VulnCategory.CORS_MISCONFIG,
}


class SARIFImporter:
    """Parse a SARIF 2.1.0 document and return Vulnerability objects."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root.resolve()

    # ------------------------------------------------------------------ public

    def parse_file(self, sarif_path: Path) -> list[Vulnerability]:
        return self.parse_json(sarif_path.read_text(encoding="utf-8"))

    def parse_json(self, sarif_text: str) -> list[Vulnerability]:
        try:
            doc = json.loads(sarif_text)
        except json.JSONDecodeError as e:
            log.error("sarif_importer: invalid JSON — %s", e)
            return []

        results: list[Vulnerability] = []
        for run in doc.get("runs", []):
            rule_map = self._build_rule_map(run)
            for result in run.get("results", []):
                vuln = self._parse_result(result, rule_map)
                if vuln is not None:
                    results.append(vuln)

        log.info("sarif_importer: parsed %d findings", len(results))
        return results

    # ----------------------------------------------------------------- private

    def _build_rule_map(self, run: dict) -> dict[str, dict]:
        """Index rules from runs[].tool.driver.rules by their id."""
        rules: dict[str, dict] = {}
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            rid = rule.get("id", "")
            if rid:
                rules[rid] = rule
        # Also check extensions (e.g. Checkmarx puts rules here).
        for ext in run.get("tool", {}).get("extensions", []):
            for rule in ext.get("rules", []):
                rid = rule.get("id", "")
                if rid:
                    rules[rid] = rule
        return rules

    def _parse_result(self, result: dict, rule_map: dict[str, dict]) -> Vulnerability | None:
        rule_id = result.get("ruleId") or result.get("rule", {}).get("id", "")
        rule_meta = rule_map.get(rule_id, {})

        severity = self._parse_severity(result, rule_meta)
        category = self._infer_category(rule_id, result, rule_meta)
        message = (
            result.get("message", {}).get("text", "")
            or rule_meta.get("shortDescription", {}).get("text", "")
            or rule_id
        )

        loc = self._parse_location(result)
        if loc is None:
            log.debug("sarif_importer: result %r has no parseable location — skipped", rule_id)
            return None

        return Vulnerability(
            category=category,
            severity=severity,
            title=message.splitlines()[0][:200],
            description=message,
            location=loc,
            rule_id=rule_id,
        )

    def _parse_severity(self, result: dict, rule_meta: dict) -> Severity:
        # 1. Check result properties (Checkmarx puts HIGH/MEDIUM here).
        props = result.get("properties", {})
        sev_str = (
            props.get("severity")
            or props.get("Severity")
            or props.get("priority")
            or ""
        )
        if sev_str:
            mapped = _SARIF_SEVERITY_MAP.get(str(sev_str).lower())
            if mapped:
                return mapped

        # 2. SARIF standard level field.
        level = result.get("level", "warning").lower()
        return _SARIF_LEVEL_MAP.get(level, Severity.MEDIUM)

    def _infer_category(self, rule_id: str, result: dict, rule_meta: dict) -> VulnCategory:
        # Try RULE_CATEGORY_MAP by rule_id fragments.
        for key, cat in RULE_CATEGORY_MAP.items():
            if key in rule_id.lower():
                return cat

        # Try CWE from result taxa or rule properties.
        cwe_ids = self._extract_cwe_ids(result, rule_meta)
        for cwe in cwe_ids:
            cat = _CWE_CATEGORY_MAP.get(cwe)
            if cat:
                return cat

        # Fallback: keyword scan on the rule_id string.
        rid = rule_id.lower()
        if "sql" in rid or "injection" in rid:
            return VulnCategory.SQL_INJECTION
        if "xss" in rid or "cross_site" in rid:
            return VulnCategory.XSS
        if "cmd" in rid or "command" in rid or "exec" in rid:
            return VulnCategory.COMMAND_INJECTION
        if "path" in rid or "traversal" in rid or "directory" in rid:
            return VulnCategory.PATH_TRAVERSAL
        if "redirect" in rid:
            return VulnCategory.OPEN_REDIRECT
        if "ssrf" in rid:
            return VulnCategory.SSRF
        if "xxe" in rid or "xml" in rid:
            return VulnCategory.XXE
        if "deserializ" in rid:
            return VulnCategory.INSECURE_DESERIALIZATION
        if "crypto" in rid or "cipher" in rid or "hash" in rid or "md5" in rid or "sha1" in rid:
            return VulnCategory.INSECURE_CRYPTO
        if "tls" in rid or "ssl" in rid or "cert" in rid:
            return VulnCategory.INSECURE_TLS
        if "auth" in rid and "z" not in rid:
            return VulnCategory.BROKEN_AUTH
        if "authz" in rid or "idor" in rid or "access" in rid:
            return VulnCategory.BROKEN_AUTHZ
        if "log" in rid or "pan" in rid or "cvv" in rid:
            return VulnCategory.SENSITIVE_LOGGING
        if "idempotent" in rid or "duplicate" in rid:
            return VulnCategory.MISSING_IDEMPOTENCY
        if "amount" in rid or "tamper" in rid:
            return VulnCategory.AMOUNT_TAMPERING
        if "cookie" in rid:
            return VulnCategory.INSECURE_COOKIE
        if "cors" in rid:
            return VulnCategory.CORS_MISCONFIG
        if "csrf" in rid:
            return VulnCategory.BROKEN_AUTH
        return VulnCategory.OTHER

    def _extract_cwe_ids(self, result: dict, rule_meta: dict) -> list[str]:
        ids: list[str] = []
        # result.taxa (SARIF standard CWE association).
        for taxon in result.get("taxa", []):
            tid = str(taxon.get("id", ""))
            if tid:
                ids.append(tid.lstrip("CWE-"))
        # rule.properties.cwe (common vendor extension).
        cwe_val = rule_meta.get("properties", {}).get("cwe", "")
        if cwe_val:
            for part in (cwe_val if isinstance(cwe_val, list) else [cwe_val]):
                ids.append(str(part).lstrip("CWE-").split(":")[0].strip())
        return ids

    def _parse_location(self, result: dict) -> CodeLocation | None:
        locations = result.get("locations", [])
        if not locations:
            return None
        phys = locations[0].get("physicalLocation", {})
        uri_raw = phys.get("artifactLocation", {}).get("uri", "")
        if not uri_raw:
            return None

        file_path = self._resolve_uri(uri_raw)
        region = phys.get("region", {})
        start_line = int(region.get("startLine", 1))
        end_line = int(region.get("endLine", start_line))
        snippet = region.get("snippet", {}).get("text", "")

        # Try reading snippet from disk if not in SARIF.
        if not snippet and file_path.exists():
            try:
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
                lo = max(0, start_line - 2)
                hi = min(len(lines), end_line + 1)
                snippet = "\n".join(lines[lo:hi])
            except OSError:
                pass

        return CodeLocation(
            file=file_path,
            start_line=start_line,
            end_line=end_line,
            snippet=snippet,
        )

    def _resolve_uri(self, uri: str) -> Path:
        """Convert a SARIF artifact URI to an absolute Path."""
        if uri.startswith("file:"):
            parsed = urlparse(uri)
            raw = unquote(parsed.path)
            # On Windows strip the leading / from /C:/...
            if raw.startswith("/") and len(raw) > 2 and raw[2] == ":":
                raw = raw[1:]
            return Path(raw)
        # Relative URI — resolve against repo root.
        return self.repo_root / uri.lstrip("/")
