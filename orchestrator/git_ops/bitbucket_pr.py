"""BitbucketEfficiencyPRCreator — opens a Bitbucket pull request for verified
efficiency refactorings (P6).

ACI's primary SCM is Bitbucket, so the efficiency PR feature needs a Bitbucket
backend alongside the GitHub one. This talks to the Bitbucket Cloud REST API
v2.0 directly (the webapp worker thread can't reach the MCP Bitbucket tool),
mirroring GitHubEfficiencyPRCreator's interface: `create_pr_from_perf_report`.

Auth: pass a workspace/repo access token (sent as Bearer) or a
"username:app_password" pair (sent as HTTP basic). verify=False because of the
corporate TLS-inspection proxy.
"""
from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any

try:
    import requests
    import urllib3 as _urllib3
    _urllib3.disable_warnings(_urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None  # type: ignore[assignment]

from .efficiency_pr_body import dedup_findings, render_efficiency_body


log = logging.getLogger("security_brain.bitbucket_pr")

DEFAULT_API_BASE = os.environ.get("BITBUCKET_API_BASE", "https://api.bitbucket.org/2.0")


class BitbucketEfficiencyPRCreator:
    def __init__(
        self,
        workspace: str,
        repo_slug: str,
        token: str | None = None,
        base_branch: str = "main",
        api_base: str = DEFAULT_API_BASE,
    ):
        if requests is None:
            raise RuntimeError("requests not installed. pip install requests")
        self.workspace = workspace
        self.repo_slug = repo_slug
        self.base_branch = base_branch
        self.api_base = api_base.rstrip("/")
        self.token = token or os.environ.get("BITBUCKET_TOKEN")
        if not self.token:
            raise RuntimeError("BITBUCKET_TOKEN not set")

    # ------------------------------------------------------------------
    def _auth_headers(self) -> dict:
        # "user:app_password" -> basic; bare token -> bearer.
        if ":" in self.token:
            import base64
            enc = base64.b64encode(self.token.encode()).decode()
            return {"Authorization": f"Basic {enc}"}
        return {"Authorization": f"Bearer {self.token}"}

    def _pr_url(self) -> str:
        return f"{self.api_base}/repositories/{self.workspace}/{self.repo_slug}/pullrequests"

    # ------------------------------------------------------------------
    def create_pr_from_perf_report(self, repo_root: Path, report: dict[str, Any]) -> str:
        verified = [
            f for f in report.get("findings", [])
            if f.get("status") == "verified" and f.get("refactoring")
        ]
        if not verified:
            log.info("no verified efficiency findings; skipping Bitbucket PR")
            return ""

        open_bodies = self._open_efficiency_pr_bodies()
        remaining, skipped = dedup_findings(verified, open_bodies)
        if skipped:
            log.info("bitbucket PR dedup: %d finding(s) already have an open PR", len(skipped))
        if not remaining:
            log.info("all verified findings already have open Bitbucket PRs; skipping")
            return ""

        from datetime import datetime, timezone
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        branch = f"efficiency/autofix-{run_id}"
        self._push_branch(repo_root, branch)
        body = render_efficiency_body(remaining, report)

        payload = {
            "title": f"[JANUS] Efficiency refactors — {len(remaining)} verified finding(s)",
            "description": body,
            "source": {"branch": {"name": branch}},
            "destination": {"branch": {"name": self.base_branch}},
            "close_source_branch": True,
        }
        resp = requests.post(
            self._pr_url(), json=payload, headers=self._auth_headers(),
            verify=False, timeout=30,
        )
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Bitbucket PR creation failed ({resp.status_code}): {resp.text[:300]}")
        data = resp.json()
        url = (data.get("links", {}).get("html", {}) or {}).get("href", "")
        log.info("opened Bitbucket efficiency PR %s", url)
        return url

    def _open_efficiency_pr_bodies(self) -> list[str]:
        bodies: list[str] = []
        try:
            resp = requests.get(
                self._pr_url(), params={"state": "OPEN", "pagelen": 50},
                headers=self._auth_headers(), verify=False, timeout=30,
            )
            if resp.status_code == 200:
                for pr in resp.json().get("values", []):
                    branch = (pr.get("source", {}).get("branch", {}) or {}).get("name", "")
                    if branch.startswith("efficiency/autofix-"):
                        bodies.append(pr.get("description") or "")
        except Exception as e:  # best-effort dedup
            log.warning("bitbucket PR dedup: could not list open PRs: %s", e)
        return bodies

    def _push_branch(self, repo_root: Path, branch: str) -> None:
        env_git = {
            "GIT_AUTHOR_NAME": "JANUSEfficiencyBrain",
            "GIT_AUTHOR_EMAIL": "janus-efficiency@aci.local",
            "GIT_COMMITTER_NAME": "JANUSEfficiencyBrain",
            "GIT_COMMITTER_EMAIL": "janus-efficiency@aci.local",
            # Bypass corporate TLS-inspection proxy for git HTTPS operations.
            "GIT_SSL_NO_VERIFY": "true",
        }
        merged_env = {**os.environ, **env_git}
        for cmd in [
            ["git", "checkout", "-B", branch],
            ["git", "add", "-A"],
            ["git", "commit", "-m", f"efficiency: verified refactors for {branch}"],
            ["git", "push", "-u", "origin", branch, "--force-with-lease"],
        ]:
            subprocess.run(cmd, cwd=repo_root, check=True, env=merged_env)
