"""Reachability analyzer — scores findings by how reachable they are via HTTP.

A finding in code that's directly registered as a web route is more urgent than
one buried in a private utility function.  This analyzer parses route registration
patterns across frameworks and annotates each Vulnerability with a
``reachability_score`` (0.0–1.0) and a ``reachability_label`` in its metadata.

Scores:
  1.0  — vulnerable code IS a route handler (directly exploitable via HTTP)
  0.8  — vulnerable code is in a file imported/used by a route handler
  0.5  — public class/function but not in a route file (reachable by callers)
  0.2  — private utility, only called internally (indirect reachability)

The score multiplies into ``Vulnerability.priority`` so high-severity
directly-routed findings sort first in the agent loop.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..models.vulnerability import Vulnerability


log = logging.getLogger("security_brain.reachability")

# Patterns that register HTTP route handlers
_ROUTE_PATTERNS: list[re.Pattern] = [
    # ASP.NET Core Minimal API: app.MapGet/Post/Put/Delete/Patch/Methods(...)
    re.compile(r'\bapp\.Map(?:Get|Post|Put|Delete|Patch|Methods)\s*\(', re.IGNORECASE),
    # ASP.NET Core controllers: [HttpGet], [HttpPost], [Route(...)]
    re.compile(r'\[(?:Http(?:Get|Post|Put|Delete|Patch)|Route)\s*[\(\]]'),
    # Python Flask / FastAPI decorators: @app.route, @router.get, @app.post, etc.
    re.compile(r'@(?:app|router|blueprint|bp)\s*\.\s*(?:route|get|post|put|delete|patch)\s*\('),
    # FastAPI: @app.get("/"), @router.post("/")
    re.compile(r'@(?:\w+)\.(?:get|post|put|delete|patch|options|head)\s*\(\s*["\'/]'),
    # Django urls.py path()/url()
    re.compile(r'\b(?:path|url|re_path)\s*\(\s*["\']'),
    # Express.js: router.get('/', ...), app.post('/api/...')
    re.compile(r'\b(?:app|router)\s*\.\s*(?:get|post|put|delete|patch|all)\s*\(\s*["\'/]'),
    # Spring @GetMapping, @PostMapping, @RequestMapping
    re.compile(r'@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*[\(\(]'),
    # JAX-RS: @GET, @POST, @Path
    re.compile(r'@(?:GET|POST|PUT|DELETE|PATCH|Path)\b'),
]

# Import / include / using patterns to follow the dependency graph
_IMPORT_PATTERNS: list[re.Pattern] = [
    re.compile(r'^\s*(?:from|import)\s+([\w.]+)', re.MULTILINE),   # Python
    re.compile(r'^\s*using\s+([\w.]+);', re.MULTILINE),            # C#
    re.compile(r'^\s*import\s+([\w.]+);', re.MULTILINE),           # Java
    re.compile(r'require\s*\(\s*["\']([^"\']+)["\']', re.MULTILINE),  # Node
]


class ReachabilityAnalyzer:
    """Annotate findings with reachability metadata in-place."""

    def analyze(self, findings: list[Vulnerability], repo_root: Path) -> None:
        route_files = self._find_route_files(repo_root)
        log.info("reachability: found %d route file(s) in %s", len(route_files), repo_root)

        for vuln in findings:
            score, label = self._score(vuln, route_files, repo_root)
            vuln.metadata["reachability_score"] = score
            vuln.metadata["reachability_label"] = label
            log.debug(
                "reachability: %s → %.1f (%s)",
                vuln.location.as_pointer(), score, label,
            )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _find_route_files(self, repo_root: Path) -> set[Path]:
        """Return the set of source files that contain HTTP route registrations."""
        route_files: set[Path] = set()
        extensions = ("*.py", "*.cs", "*.java", "*.ts", "*.js")
        for ext in extensions:
            for f in repo_root.rglob(ext):
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if any(p.search(text) for p in _ROUTE_PATTERNS):
                    route_files.add(f.resolve())
        return route_files

    def _score(
        self, vuln: Vulnerability, route_files: set[Path], repo_root: Path
    ) -> tuple[float, str]:
        vuln_file = vuln.location.file.resolve()

        # Direct: the vulnerable file is itself a route file
        if vuln_file in route_files:
            return 1.0, "direct-route"

        # One-hop: a route file imports/references the vulnerable file by name
        stem = vuln_file.stem  # e.g. "payments_service"
        for rf in route_files:
            try:
                text = rf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # Check for the module/class stem in any import statement
            if stem in text:
                return 0.8, "imported-by-route"

        # Check if the snippet contains a public symbol (def, class, public method)
        snippet = vuln.location.snippet or ""
        is_public = bool(
            re.search(r'\bpublic\b', snippet)               # Java / C#
            or re.search(r'^def\s+[a-z]', snippet, re.M)   # Python public function
            or re.search(r'^class\s+\w', snippet, re.M)    # class
        )
        if is_public:
            return 0.5, "public-symbol"

        return 0.2, "private-utility"
