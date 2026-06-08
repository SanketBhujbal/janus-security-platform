"""Checkmarx One API connector.

Authenticates against Checkmarx One via OAuth2 client credentials, fetches
findings for a specific scan, and converts them to Vulnerability objects that
the SecurityBrain exploit→patch→validate pipeline can process.

Usage:
    connector = CheckmarxConnector(
        base_url="https://eu.checkmarx.net",
        tenant="my-company",
        client_id="...",
        client_secret="...",
    )
    vulns = connector.fetch_findings(scan_id="<uuid>", repo_root=Path("/code"))
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ..models.vulnerability import (
    CodeLocation,
    Severity,
    VulnCategory,
    Vulnerability,
)

log = logging.getLogger("security_brain.checkmarx_connector")

_CX_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
    "INFO":     Severity.INFO,
}

# Map Checkmarx queryName fragments to VulnCategory.
_CX_QUERY_MAP: list[tuple[str, VulnCategory]] = [
    ("SQL_Injection",             VulnCategory.SQL_INJECTION),
    ("Blind_SQL",                 VulnCategory.SQL_INJECTION),
    ("HQL_Injection",             VulnCategory.SQL_INJECTION),
    ("XSS",                       VulnCategory.XSS),
    ("Cross_Site_Scripting",      VulnCategory.XSS),
    ("Command_Injection",         VulnCategory.COMMAND_INJECTION),
    ("OS_Command",                VulnCategory.COMMAND_INJECTION),
    ("Path_Traversal",            VulnCategory.PATH_TRAVERSAL),
    ("Open_Redirect",             VulnCategory.OPEN_REDIRECT),
    ("SSRF",                      VulnCategory.SSRF),
    ("Server_Side_Request",       VulnCategory.SSRF),
    ("XXE",                       VulnCategory.XXE),
    ("XML_External",              VulnCategory.XXE),
    ("Deserialization",           VulnCategory.INSECURE_DESERIALIZATION),
    ("Insecure_Deserialization",  VulnCategory.INSECURE_DESERIALIZATION),
    ("Broken_Authentication",     VulnCategory.BROKEN_AUTH),
    ("Missing_JWT",               VulnCategory.BROKEN_AUTH),
    ("Weak_JWT",                  VulnCategory.BROKEN_AUTH),
    ("IDOR",                      VulnCategory.BROKEN_AUTHZ),
    ("Authorization",             VulnCategory.BROKEN_AUTHZ),
    ("Hardcoded_Password",        VulnCategory.OTHER),
    ("Hardcoded_Secret",          VulnCategory.OTHER),
    ("Sensitive_Cookie",          VulnCategory.INSECURE_COOKIE),
    ("Missing_HttpOnly",          VulnCategory.INSECURE_COOKIE),
    ("CORS",                      VulnCategory.CORS_MISCONFIG),
    ("CSRF",                      VulnCategory.BROKEN_AUTH),
    ("Weak_Cryptography",         VulnCategory.INSECURE_CRYPTO),
    ("Insecure_Random",           VulnCategory.INSECURE_CRYPTO),
    ("Broken_Crypto",             VulnCategory.INSECURE_CRYPTO),
    ("Cleartext_Transmission",    VulnCategory.INSECURE_TLS),
    ("Missing_Encryption",        VulnCategory.INSECURE_TLS),
    ("Log_Injection",             VulnCategory.SENSITIVE_LOGGING),
    ("Sensitive_Data_Exposure",   VulnCategory.SENSITIVE_LOGGING),
    ("Missing_Idempotency",       VulnCategory.MISSING_IDEMPOTENCY),
    ("Amount_Tampering",          VulnCategory.AMOUNT_TAMPERING),
    ("Race_Condition",            VulnCategory.RACE_CONDITION),
    ("TOCTOU",                    VulnCategory.RACE_CONDITION),
]


class CheckmarxConnector:
    """Pull findings from Checkmarx One via its REST API."""

    IAM_URL_TEMPLATE = "https://iam.checkmarx.net/auth/realms/{tenant}/protocol/openid-connect/token"

    def __init__(
        self,
        base_url: str,
        tenant: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.tenant = tenant
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: str | None = None

    # ------------------------------------------------------------------ public

    def fetch_findings(self, scan_id: str, repo_root: Path) -> list[Vulnerability]:
        """Fetch and convert all findings for a Checkmarx scan."""
        try:
            import requests  # noqa: PLC0415
        except ImportError:
            raise RuntimeError(
                "requests is required for the Checkmarx connector. "
                "Install with: pip install requests"
            )

        self._authenticate(requests)
        raw_results = self._fetch_results(requests, scan_id)
        log.info("checkmarx_connector: fetched %d raw results for scan %s", len(raw_results), scan_id)

        vulns: list[Vulnerability] = []
        repo_root = repo_root.resolve()
        for item in raw_results:
            vuln = self._convert(item, repo_root)
            if vuln is not None:
                vulns.append(vuln)
        log.info("checkmarx_connector: converted %d findings", len(vulns))
        return vulns

    def test_connection(self) -> bool:
        """Return True if authentication succeeds."""
        try:
            import requests  # noqa: PLC0415
            self._authenticate(requests)
            return True
        except Exception as e:
            log.warning("checkmarx_connector: connection test failed: %s", e)
            return False

    # ----------------------------------------------------------------- private

    def _authenticate(self, requests: Any) -> None:
        iam_url = self.IAM_URL_TEMPLATE.format(tenant=self.tenant)
        resp = requests.post(
            iam_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=30,
        )
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        log.info("checkmarx_connector: authenticated as %s", self.client_id)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json; version=1.0",
        }

    def _fetch_results(self, requests: Any, scan_id: str) -> list[dict]:
        """Page through /api/results until all findings are fetched."""
        results: list[dict] = []
        limit = 100
        offset = 0
        while True:
            url = f"{self.base_url}/api/results"
            resp = requests.get(
                url,
                headers=self._headers(),
                params={
                    "scan-id": scan_id,
                    "limit": limit,
                    "offset": offset,
                },
                timeout=60,
            )
            resp.raise_for_status()
            page = resp.json()
            batch = page.get("results", [])
            results.extend(batch)
            if len(batch) < limit:
                break
            offset += limit
        return results

    def _convert(self, item: dict, repo_root: Path) -> Vulnerability | None:
        severity_str = item.get("severity", "MEDIUM").upper()
        severity = _CX_SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        details = item.get("vulnerabilityDetails", {})
        query_name = details.get("queryName", item.get("id", "unknown"))
        description = details.get("description", query_name)
        cwe_id = str(details.get("cweId", ""))

        category = self._infer_category(query_name, cwe_id)

        loc = self._parse_location(item, repo_root)
        if loc is None:
            return None

        return Vulnerability(
            category=category,
            severity=severity,
            title=query_name.replace("_", " "),
            description=description or query_name,
            location=loc,
            rule_id=f"checkmarx.{query_name.lower()}",
        )

    def _infer_category(self, query_name: str, cwe_id: str) -> VulnCategory:
        for fragment, cat in _CX_QUERY_MAP:
            if fragment.lower() in query_name.lower():
                return cat
        # CWE fallback (re-use the same map as SARIF importer).
        from .sarif_importer import _CWE_CATEGORY_MAP  # noqa: PLC0415
        if cwe_id and cwe_id in _CWE_CATEGORY_MAP:
            return _CWE_CATEGORY_MAP[cwe_id]
        return VulnCategory.OTHER

    def _parse_location(self, item: dict, repo_root: Path) -> CodeLocation | None:
        nodes = item.get("nodes", [])
        if not nodes:
            return None
        node = nodes[0]
        raw_path = node.get("fileName", "")
        if not raw_path:
            return None

        # CX paths are like "/src/main/java/PaymentService.java"
        rel = raw_path.lstrip("/\\")
        file_path = repo_root / rel
        line = int(node.get("line", 1))

        snippet = ""
        if file_path.exists():
            try:
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
                lo = max(0, line - 2)
                hi = min(len(lines), line + 2)
                snippet = "\n".join(lines[lo:hi])
            except OSError:
                pass

        return CodeLocation(
            file=file_path,
            start_line=line,
            end_line=line,
            snippet=snippet,
        )
