"""Compliance report generator.

Maps each vulnerability category to the relevant PCI-DSS, OWASP Top 10,
SOC 2, and NIST 800-53 control references and renders a self-contained HTML
report suitable for sharing with auditors or a product owner.

Usage:
    from orchestrator.report.compliance import ComplianceReporter
    ComplianceReporter().generate(report_dict, output_path)
"""
from __future__ import annotations

import html
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


log = logging.getLogger("security_brain.compliance")

# ---------------------------------------------------------------------------
# Compliance mapping: vulnerability category → framework control references
# ---------------------------------------------------------------------------

COMPLIANCE_MAP: dict[str, dict[str, Any]] = {
    "sensitive_logging": {
        "pci_dss": ["3.3.1 - Do not retain SAD post-auth", "3.3.2 - Encrypt SAD if retained", "3.4 - Render PAN unreadable"],
        "owasp": ["A09:2021 - Security Logging and Monitoring Failures"],
        "soc2": ["CC7.2 - Monitor system components for anomalies"],
        "nist": ["AU-3 - Content of audit records", "SI-12 - Information management"],
        "summary": "Sensitive authentication data (PAN, CVV, track data) must never be written to logs.",
    },
    "amount_tampering": {
        "pci_dss": ["6.2.4 - Prevent common vulnerabilities", "6.4.1 - Protect public-facing web apps"],
        "owasp": ["A04:2021 - Insecure Design", "A03:2021 - Injection"],
        "soc2": ["CC6.1 - Logical access security", "CC8.1 - Change management"],
        "nist": ["SI-10 - Information input validation", "AC-4 - Information flow enforcement"],
        "summary": "Payment amounts must be reconciled server-side against the authoritative order record.",
    },
    "missing_idempotency": {
        "pci_dss": ["6.2.4 - Prevent common vulnerabilities", "10.2 - Implement audit logs"],
        "owasp": ["A04:2021 - Insecure Design"],
        "soc2": ["CC6.6 - Transmission integrity", "CC7.1 - System monitoring"],
        "nist": ["SC-5 - Denial of service protection", "SI-10 - Information input validation"],
        "summary": "Mutating payment endpoints must implement idempotency-key deduplication to prevent double charges.",
    },
    "sql_injection": {
        "pci_dss": ["6.2.4 - Prevent injection flaws", "6.4.1 - Protect web-facing systems"],
        "owasp": ["A03:2021 - Injection"],
        "soc2": ["CC6.1 - Logical access", "CC6.6 - Transmission integrity"],
        "nist": ["SI-10 - Input validation", "SA-15 - Development process"],
        "summary": "All database queries must use parameterized statements or prepared queries.",
    },
    "nosql_injection": {
        "pci_dss": ["6.2.4 - Prevent injection flaws"],
        "owasp": ["A03:2021 - Injection"],
        "soc2": ["CC6.1 - Logical access"],
        "nist": ["SI-10 - Input validation"],
        "summary": "NoSQL queries must sanitize operator fields ($ne, $gt, $regex) from user input.",
    },
    "xss": {
        "pci_dss": ["6.2.4 - Prevent XSS", "6.4.1 - Protect web-facing systems"],
        "owasp": ["A03:2021 - Injection"],
        "soc2": ["CC6.1 - Logical access"],
        "nist": ["SI-10 - Input validation", "SC-28 - Protection of information at rest"],
        "summary": "All user-controlled output must be HTML-encoded before rendering.",
    },
    "broken_auth": {
        "pci_dss": ["8.2 - Identify users and authenticate", "8.3 - Strong authentication"],
        "owasp": ["A07:2021 - Identification and Authentication Failures"],
        "soc2": ["CC6.1 - Logical access", "CC6.2 - Identification and authentication"],
        "nist": ["IA-2 - Identification and authentication", "AC-7 - Unsuccessful login attempts"],
        "summary": "Authentication mechanisms must enforce MFA, secure session tokens, and brute-force protection.",
    },
    "broken_authz": {
        "pci_dss": ["7.1 - Limit access to system components", "7.2 - Establish access control"],
        "owasp": ["A01:2021 - Broken Access Control"],
        "soc2": ["CC6.1 - Logical access security"],
        "nist": ["AC-3 - Access enforcement", "AC-6 - Least privilege"],
        "summary": "Authorization checks must be enforced server-side for every resource access.",
    },
    "duplicate_payment": {
        "pci_dss": ["6.2.4 - Prevent logic flaws", "10.2 - Audit logs"],
        "owasp": ["A04:2021 - Insecure Design"],
        "soc2": ["CC6.6 - Transmission integrity"],
        "nist": ["SI-10 - Input validation", "SC-5 - DoS protection"],
        "summary": "Payment processing must deduplicate idempotency keys to prevent double-charge on replay.",
    },
    "command_injection": {
        "pci_dss": ["6.2.4 - Prevent OS command injection"],
        "owasp": ["A03:2021 - Injection"],
        "soc2": ["CC6.1 - Logical access"],
        "nist": ["SI-10 - Input validation", "CM-7 - Least functionality"],
        "summary": "Shell commands must not be constructed from user-controlled strings.",
    },
    "path_traversal": {
        "pci_dss": ["6.2.4 - Prevent path traversal"],
        "owasp": ["A01:2021 - Broken Access Control"],
        "soc2": ["CC6.1 - Logical access"],
        "nist": ["AC-3 - Access enforcement", "SI-10 - Input validation"],
        "summary": "File paths derived from user input must be canonicalized and confined to allowed directories.",
    },
    "insecure_crypto": {
        "pci_dss": ["3.5 - Protect keys", "4.2.1 - Use strong cryptography"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "soc2": ["CC6.7 - Transmission of information"],
        "nist": ["SC-8 - Transmission confidentiality", "SC-28 - Protection at rest"],
        "summary": "Cryptographic operations must use approved algorithms (AES-256, RSA-2048+, SHA-256+).",
    },
    "insecure_tls": {
        "pci_dss": ["4.2.1 - Use TLS 1.2+", "4.2.2 - Inventory trusted keys and certificates"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "soc2": ["CC6.7 - Transmission of information"],
        "nist": ["SC-8 - Transmission confidentiality"],
        "summary": "All payment data in transit must use TLS 1.2 or higher with valid certificates.",
    },
    "ssrf": {
        "pci_dss": ["6.4.1 - Protect web-facing systems"],
        "owasp": ["A10:2021 - Server-Side Request Forgery"],
        "soc2": ["CC6.1 - Logical access"],
        "nist": ["SC-7 - Boundary protection", "CA-3 - System interconnections"],
        "summary": "Server-side HTTP requests must not be constructed from unvalidated user-supplied URLs.",
    },
    "race_condition": {
        "pci_dss": ["6.2.4 - Prevent logic flaws"],
        "owasp": ["A04:2021 - Insecure Design"],
        "soc2": ["CC6.6 - Transmission integrity"],
        "nist": ["SI-10 - Input validation", "SC-5 - DoS protection"],
        "summary": "Concurrent mutations to shared financial state must be protected by appropriate locks or atomic operations.",
    },
    "weak_payment_validation": {
        "pci_dss": ["6.2.4 - Validate input", "4.2 - Protect cardholder data"],
        "owasp": ["A04:2021 - Insecure Design"],
        "soc2": ["CC6.1 - Logical access"],
        "nist": ["SI-10 - Input validation"],
        "summary": "All payment fields (amount, currency, card number) must be validated server-side before processing.",
    },
    "logic_flaw": {
        "pci_dss": ["6.2.4 - Prevent logic flaws", "6.4.1 - Protect web-facing systems"],
        "owasp": ["A04:2021 - Insecure Design"],
        "soc2": ["CC8.1 - Change management"],
        "nist": ["SA-8 - Security and privacy engineering principles"],
        "summary": "Business logic must enforce state-machine transitions and prevent out-of-sequence or duplicate operations.",
    },
    "cors_misconfig": {
        "pci_dss": ["6.4.1 - Protect web-facing systems"],
        "owasp": ["A01:2021 - Broken Access Control"],
        "soc2": ["CC6.1 - Logical access"],
        "nist": ["SC-7 - Boundary protection"],
        "summary": "CORS policies must restrict origins to explicitly trusted domains.",
    },
    "insecure_deserialization": {
        "pci_dss": ["6.2.4 - Prevent deserialization attacks"],
        "owasp": ["A08:2021 - Software and Data Integrity Failures"],
        "soc2": ["CC6.1 - Logical access"],
        "nist": ["SI-10 - Input validation", "SI-7 - Software firmware integrity"],
        "summary": "Untrusted serialized data must be validated and deserialized using safe parsers only.",
    },
    "xxe": {
        "pci_dss": ["6.2.4 - Prevent XML injection"],
        "owasp": ["A05:2021 - Security Misconfiguration"],
        "soc2": ["CC6.1 - Logical access"],
        "nist": ["SI-10 - Input validation"],
        "summary": "XML parsers must have external entity processing disabled (XXE prevention).",
    },
    "open_redirect": {
        "pci_dss": ["6.4.1 - Protect web-facing systems"],
        "owasp": ["A01:2021 - Broken Access Control"],
        "soc2": ["CC6.1 - Logical access"],
        "nist": ["SI-10 - Input validation"],
        "summary": "Redirect targets must be validated against an allowlist of trusted URLs.",
    },
    "session_misuse": {
        "pci_dss": ["8.2 - Identify users", "8.3.2 - Authenticate users"],
        "owasp": ["A07:2021 - Identification and Authentication Failures"],
        "soc2": ["CC6.2 - Identification and authentication"],
        "nist": ["IA-5 - Authenticator management", "SC-23 - Session authenticity"],
        "summary": "Session tokens must be invalidated on logout, must not be reused across users, and must have bounded lifetimes.",
    },
    "timing_attack": {
        "pci_dss": ["8.3 - Strong authentication"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "soc2": ["CC6.2 - Authentication"],
        "nist": ["IA-5 - Authenticator management"],
        "summary": "Secrets and tokens must be compared using constant-time comparison functions.",
    },
    "insecure_cookie": {
        "pci_dss": ["6.4.1 - Protect web-facing systems"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "soc2": ["CC6.7 - Transmission of information"],
        "nist": ["SC-8 - Transmission confidentiality"],
        "summary": "Session cookies must carry Secure, HttpOnly, and SameSite=Strict attributes.",
    },
    "other": {
        "pci_dss": ["6.2.4 - Address vulnerabilities"],
        "owasp": ["A04:2021 - Insecure Design"],
        "soc2": ["CC7.1 - System monitoring"],
        "nist": ["SI-2 - Flaw remediation"],
        "summary": "Custom business-logic vulnerability — review against applicable controls.",
    },
}

# OWASP Top 10 short labels for the badge display
OWASP_COLORS: dict[str, str] = {
    "A01": "#e74c3c",
    "A02": "#e67e22",
    "A03": "#f39c12",
    "A04": "#2ecc71",
    "A05": "#1abc9c",
    "A06": "#3498db",
    "A07": "#9b59b6",
    "A08": "#e91e63",
    "A09": "#607d8b",
    "A10": "#795548",
}

STATUS_COLORS: dict[str, str] = {
    "validated": "#27ae60",
    "patched": "#2980b9",
    "exploited": "#e67e22",
    "failed": "#c0392b",
    "discovered": "#7f8c8d",
    "suppressed": "#bdc3c7",
}

SEVERITY_COLORS: dict[str, str] = {
    "critical": "#c0392b",
    "high": "#e67e22",
    "medium": "#f39c12",
    "low": "#3498db",
    "info": "#95a5a6",
}


class ComplianceReporter:
    def generate(self, report: dict[str, Any], output_path: Path) -> None:
        html_content = self._render(report)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html_content, encoding="utf-8")
        log.info("compliance_reporter: wrote %s", output_path)

    def generate_dict(self, report: dict[str, Any]) -> dict[str, Any]:
        """Return a compliance summary dict (for JSON reports and the API)."""
        findings = report.get("findings", [])
        by_framework: dict[str, list[str]] = {"pci_dss": [], "owasp": [], "soc2": [], "nist": []}
        coverage: list[dict] = []

        for f in findings:
            cat = f.get("category", "other")
            mapping = COMPLIANCE_MAP.get(cat, COMPLIANCE_MAP["other"])
            refs: dict[str, list[str]] = {}
            for fw in ("pci_dss", "owasp", "soc2", "nist"):
                controls = mapping.get(fw, [])
                refs[fw] = controls
                for c in controls:
                    if c not in by_framework[fw]:
                        by_framework[fw].append(c)
            coverage.append({
                "category": cat,
                "status": f.get("status"),
                "severity": f.get("severity"),
                "title": f.get("title"),
                "location": f.get("location", {}).get("file"),
                "compliance_refs": refs,
                "summary": mapping.get("summary", ""),
            })

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": report.get("mode"),
            "totals": {
                "scanned": report.get("scanned", 0),
                "exploited": report.get("exploited", 0),
                "patched": report.get("patched", 0),
                "validated": report.get("validated", 0),
                "failed": report.get("failed", 0),
            },
            "framework_controls_triggered": by_framework,
            "findings": coverage,
        }

    # ------------------------------------------------------------------
    # HTML renderer
    # ------------------------------------------------------------------

    def _render(self, report: dict[str, Any]) -> str:
        findings = report.get("findings", [])
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        rows = "".join(self._finding_row(i, f) for i, f in enumerate(findings, 1))
        summary_cards = self._summary_cards(report)
        framework_table = self._framework_table(findings)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Compliance Report — Agentic Security Platform</title>
<style>
  body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         margin:0; padding:24px; background:#f5f6fa; color:#2c3e50; }}
  h1   {{ font-size:1.6rem; margin-bottom:4px; }}
  .ts  {{ color:#7f8c8d; font-size:.85rem; margin-bottom:24px; }}
  .cards {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:32px; }}
  .card  {{ background:#fff; border-radius:8px; padding:16px 24px; min-width:120px;
            box-shadow:0 1px 4px rgba(0,0,0,.08); text-align:center; }}
  .card .num {{ font-size:2rem; font-weight:700; }}
  .card .lbl {{ font-size:.8rem; color:#7f8c8d; text-transform:uppercase; letter-spacing:.05em; }}
  table {{ width:100%; border-collapse:collapse; background:#fff;
           border-radius:8px; overflow:hidden;
           box-shadow:0 1px 4px rgba(0,0,0,.08); margin-bottom:32px; }}
  th {{ background:#34495e; color:#fff; padding:10px 14px; text-align:left;
        font-size:.82rem; text-transform:uppercase; letter-spacing:.04em; }}
  td {{ padding:10px 14px; font-size:.88rem; border-bottom:1px solid #ecf0f1;
        vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  .badge {{ display:inline-block; border-radius:4px; padding:2px 8px; font-size:.75rem;
            font-weight:600; color:#fff; margin:2px 2px 2px 0; white-space:nowrap; }}
  .pill  {{ display:inline-block; border-radius:12px; padding:2px 10px; font-size:.75rem;
            font-weight:600; color:#fff; }}
  code {{ background:#ecf0f1; border-radius:3px; padding:1px 5px; font-size:.82em; }}
  h2 {{ font-size:1.1rem; margin:32px 0 12px; color:#34495e; }}
  details summary {{ cursor:pointer; font-weight:600; color:#2980b9; }}
  .ctrl-list {{ margin:0; padding-left:18px; }}
  .ctrl-list li {{ margin:2px 0; }}
</style>
</head>
<body>
<h1>Agentic Security Platform — Compliance Report</h1>
<div class="ts">Generated {html.escape(now)}</div>

{summary_cards}

<h2>Framework Controls Triggered</h2>
{framework_table}

<h2>Finding Detail</h2>
<table>
<thead>
  <tr>
    <th>#</th><th>Category</th><th>Severity</th><th>Status</th>
    <th>Location</th><th>PCI-DSS</th><th>OWASP</th><th>SOC 2</th><th>NIST 800-53</th>
  </tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"""

    def _summary_cards(self, report: dict) -> str:
        metrics = [
            ("Scanned", report.get("scanned", 0), "#34495e"),
            ("Exploited", report.get("exploited", 0), "#e67e22"),
            ("Patched", report.get("patched", 0), "#2980b9"),
            ("Validated", report.get("validated", 0), "#27ae60"),
            ("Failed", report.get("failed", 0), "#c0392b"),
        ]
        cards = "".join(
            f'<div class="card"><div class="num" style="color:{color}">{n}</div>'
            f'<div class="lbl">{label}</div></div>'
            for label, n, color in metrics
        )
        return f'<div class="cards">{cards}</div>'

    def _framework_table(self, findings: list[dict]) -> str:
        fw_controls: dict[str, set[str]] = {
            "pci_dss": set(), "owasp": set(), "soc2": set(), "nist": set(),
        }
        for f in findings:
            cat = f.get("category", "other")
            mapping = COMPLIANCE_MAP.get(cat, COMPLIANCE_MAP["other"])
            for fw in fw_controls:
                for ctrl in mapping.get(fw, []):
                    fw_controls[fw].add(ctrl)

        labels = {"pci_dss": "PCI-DSS", "owasp": "OWASP Top 10", "soc2": "SOC 2", "nist": "NIST 800-53"}
        rows = ""
        for fw, label in labels.items():
            controls = sorted(fw_controls[fw])
            if not controls:
                continue
            items = "".join(f"<li><code>{html.escape(c)}</code></li>" for c in controls)
            rows += f"<tr><td><strong>{html.escape(label)}</strong></td><td><ul class='ctrl-list'>{items}</ul></td></tr>"

        return f"<table><thead><tr><th>Framework</th><th>Controls Triggered</th></tr></thead><tbody>{rows}</tbody></table>"

    def _finding_row(self, idx: int, f: dict) -> str:
        cat = f.get("category", "other")
        mapping = COMPLIANCE_MAP.get(cat, COMPLIANCE_MAP["other"])
        status = f.get("status", "discovered")
        severity = f.get("severity", "info")
        loc = f.get("location") or {}
        file_str = loc.get("file", "") if isinstance(loc, dict) else str(loc)
        start = loc.get("start_line", "") if isinstance(loc, dict) else ""

        status_color = STATUS_COLORS.get(status, "#95a5a6")
        sev_color = SEVERITY_COLORS.get(severity, "#95a5a6")

        def badges(items: list[str], color: str) -> str:
            return "".join(
                f'<span class="badge" style="background:{_owasp_color(item) if "OWASP" not in item else _owasp_color(item)}">'
                f'{html.escape(item[:50])}</span>'
                for item in items
            )

        pci = badges(mapping.get("pci_dss", []), "#e74c3c")
        owasp = badges(mapping.get("owasp", []), "#e67e22")
        soc2 = badges(mapping.get("soc2", []), "#3498db")
        nist = badges(mapping.get("nist", []), "#8e44ad")

        loc_str = f"{html.escape(str(file_str))}:{start}" if start else html.escape(str(file_str))

        return (
            f"<tr>"
            f"<td>{idx}</td>"
            f"<td><code>{html.escape(cat)}</code><br><small style='color:#7f8c8d'>{html.escape(f.get('title','')[:60])}</small></td>"
            f"<td><span class='pill' style='background:{sev_color}'>{html.escape(severity)}</span></td>"
            f"<td><span class='pill' style='background:{status_color}'>{html.escape(status)}</span></td>"
            f"<td><code style='font-size:.78em'>{loc_str}</code></td>"
            f"<td>{pci}</td>"
            f"<td>{owasp}</td>"
            f"<td>{soc2}</td>"
            f"<td>{nist}</td>"
            f"</tr>"
        )


def _owasp_color(label: str) -> str:
    for code, color in OWASP_COLORS.items():
        if code in label:
            return color
    return "#607d8b"
