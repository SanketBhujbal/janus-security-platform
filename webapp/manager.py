"""Scan lifecycle management.

Each browser-initiated scan becomes a ScanRunner. The runner spins the
synchronous SecurityBrain on a worker thread, but exposes an asyncio.Queue
of progress events so the FastAPI SSE endpoint can stream them.

Completed/failed scans are written to disk via webapp.store.ScanStore so
they survive webapp restarts -- otherwise a redeploy would orphan every
browser tab pointing at a previous scan_id.
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orchestrator.events import SCAN_DONE, SCAN_ERROR, make_event
from orchestrator.llm.canned import CannedLLM
from orchestrator.llm.claude_client import LLMClient
from orchestrator.models.vulnerability import Severity
from orchestrator.orchestrator import LoopReport, SecurityBrain

from .store import ScanStore, StoredScan


log = logging.getLogger("webapp.manager")

ROOT = Path(__file__).resolve().parents[1]
RULES_ROOT = ROOT / "orchestrator" / "rules"
DEFAULT_STORE = ROOT / ".security_workdir" / "scans"
# Scan with every bundled rule set by default. Semgrep automatically skips
# rules whose declared `languages:` don't match the files in the target, so
# bundling .NET + Python + Angular here is free for repos that don't use them.
DEFAULT_RULES = [
    RULES_ROOT / "payments",          # Python / Flask payments rules
    RULES_ROOT / "payments_dotnet",   # C# / .NET / appsettings.json
    RULES_ROOT / "payments_angular",  # Angular / TypeScript
    RULES_ROOT / "payments_java",     # Java / Spring Boot / JJWT
]


@dataclass
class ScanParams:
    repo: Path
    mode: str = "scan-only"       # "scan-only" | "full" | "efficiency" | "efficiency-profile"
                                  # | "import-sarif" | "import-checkmarx"
    min_severity: Severity = Severity.MEDIUM
    max_findings: int = 200
    target_endpoint: str | None = None
    # Full-loop only -- needed for the validator to rebuild the target
    # container between patch and exploit replay.
    compose_file: Path | None = None
    compose_service: str | None = None
    health_url: str | None = None
    # Validator gate run after each patch (cwd = target repo). Defaults to
    # pytest for the Python target; the .NET demo overrides this with
    # `dotnet build` so the gate is "does the patch still compile?".
    test_command: list[str] | None = None
    # Efficiency mode only -- defines the "calls per year" projection for
    # the savings calculator. Defaults to ~10k calls/day = 3.6M/year.
    calls_per_year: int = 3_600_000
    # Tunable savings assumptions (P2). grid_region picks a carbon intensity
    # preset; cpu_cost / watts model the instance the workload runs on.
    cpu_cost_per_hour_usd: float | None = None
    grid_region: str | None = None
    avg_cpu_power_watts: float | None = None
    # Runtime profile import (P7): raw JSON (native hints / flat map / speedscope)
    # that overrides per-function call rates so savings reflect real hotness.
    profile_json: str | None = None
    # Optional: if set, the brain will open a GitHub PR after validated/verified findings.
    # Format: "owner/repo-name". Requires GITHUB_TOKEN env var or github_token field.
    github_repo_slug: str | None = None
    github_token: str | None = None
    github_base_branch: str = "main"
    # Bitbucket PR backend (P6). When pr_provider="bitbucket" and the workspace
    # + repo slug are set, efficiency PRs go to Bitbucket instead of GitHub.
    pr_provider: str = "github"
    bitbucket_workspace: str | None = None
    bitbucket_repo_slug: str | None = None
    bitbucket_token: str | None = None
    # CI guard mode (P5).
    ci_base_ref: str = "origin/main"
    ci_fail_severity: Severity = Severity.HIGH
    ci_pr_number: int | None = None
    # Import-mode fields ---------------------------------------------------
    sarif_content: str | None = None          # raw SARIF JSON (import-sarif mode)
    checkmarx_url: str | None = None          # e.g. "https://eu.checkmarx.net"
    checkmarx_tenant: str | None = None
    checkmarx_client_id: str | None = None
    checkmarx_client_secret: str | None = None
    checkmarx_scan_id: str | None = None


@dataclass
class ScanRunner:
    scan_id: str
    params: ScanParams
    loop: asyncio.AbstractEventLoop
    store: ScanStore
    queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    status: str = "queued"        # queued | running | done | error
    report: LoopReport | None = None
    error: str | None = None
    findings_index: dict[int, dict] = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""

    def emit(self, type: str, message: str, **data: Any) -> None:
        # Called from the worker thread; hand off to the event loop.
        event = make_event(type, message, **data)
        self.loop.call_soon_threadsafe(self.queue.put_nowait, event)
        # Cache finding payloads so the detail endpoint can serve them after
        # the SSE stream has closed.
        if type == "finding_discovered":
            idx = data.get("idx")
            if isinstance(idx, int):
                self.findings_index[idx] = dict(data)

    def _build_llm(self) -> LLMClient | None:
        # Preference order:
        #   1. Claude Agent SDK (uses Claude Code login -- no API key needed)
        #   2. Anthropic API SDK (uses ANTHROPIC_API_KEY)
        #   3. CannedLLM (offline; covers the 7 seeded vulnerabilities only)
        # Override the order with WEBAPP_LLM_BACKEND env var: agent_sdk / api_key / canned.
        backend = os.environ.get("WEBAPP_LLM_BACKEND", "").strip().lower()
        if backend == "canned":
            return CannedLLM()
        if backend == "api_key":
            from orchestrator.llm.claude_client import ClaudeClient
            return ClaudeClient()
        # Default: try Agent SDK first, wrapped in a fallback so that a
        # CLIConnectionError on the first real call (which happens when the
        # webapp runs outside a Claude Code session) transparently retries
        # with ANTHROPIC_API_KEY or CannedLLM instead of crashing the scan.
        try:
            from orchestrator.llm.agent_sdk_client import ClaudeAgentSDKClient
            sdk_client = ClaudeAgentSDKClient()
            log.info("LLM backend: claude-agent-sdk (uses Claude Code login)")
            return _AgentSDKWithFallback(sdk_client, self._make_fallback_llm)
        except Exception as e:
            log.warning("Agent SDK unavailable (%s); trying ANTHROPIC_API_KEY", e)
        return self._make_fallback_llm()

    def _make_fallback_llm(self) -> LLMClient:
        if os.environ.get("ANTHROPIC_API_KEY"):
            from orchestrator.llm.claude_client import ClaudeClient
            log.info("LLM backend: anthropic API key")
            return ClaudeClient()
        log.warning("LLM backend: CannedLLM (offline -- only seeded vulns supported)")
        return CannedLLM()

    def _docker_available(self) -> bool:
        import shutil
        if shutil.which("docker") is None:
            return False
        # Even if the binary exists, the daemon might be down.
        import subprocess
        try:
            r = subprocess.run(["docker", "info"], capture_output=True, timeout=3)
            return r.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def _build_runner_and_deployer(self):
        # Only used in full-loop mode. Picks Docker if available; otherwise
        # falls back to the subprocess implementations so the demo still runs.
        if self.params.mode == "scan-only":
            return None, None

        docker_ok = self._docker_available()

        if docker_ok and self.params.compose_file and self.params.compose_service:
            # Full Docker setup: custom sandbox image + compose target deployer.
            from orchestrator.exploits.runner import SandboxRunner
            from orchestrator.sandbox.target_deployer import ComposeTargetDeployer
            runner = SandboxRunner()
            deployer = ComposeTargetDeployer(
                compose_file=self.params.compose_file,
                service=self.params.compose_service,
                health_url=self.params.health_url,
            )
            log.info("full-loop backend: Docker (SandboxRunner + ComposeTargetDeployer)")
            return runner, deployer

        # Build the deployer (shared by both Docker and subprocess paths below).
        from orchestrator.sandbox.subprocess_deployer import SubprocessTargetDeployer
        launch = self._infer_target_launch()
        deployer = None
        if launch is not None:
            command, cwd, extra_env, target_script = launch
            deployer = SubprocessTargetDeployer(
                target_script=target_script,
                command=command,
                cwd=cwd,
                env=extra_env,
                health_url=self.params.health_url,
                startup_seconds=2.0 if command else 0.5,
            )
        else:
            log.warning(
                "full-loop mode: no runnable target found (app.py / .csproj); "
                "the validator's redeploy step will be skipped."
            )

        if docker_ok:
            # Docker available but no compose file — use DockerSandboxRunner for
            # exploit isolation while still launching the target as a subprocess.
            from orchestrator.exploits.docker_runner import DockerSandboxRunner
            log.info(
                "full-loop backend: DockerSandboxRunner (isolated exploits) + "
                "SubprocessTargetDeployer (target on host)"
            )
            return DockerSandboxRunner(), deployer

        # No Docker at all -> fully subprocess. Only safe against trusted local targets.
        from orchestrator.exploits.subprocess_runner import SubprocessRunner
        log.warning(
            "full-loop backend: SUBPROCESS (no Docker). LLM-generated exploit "
            "code will run on the host with NO isolation. Trusted targets only."
        )
        return SubprocessRunner(), deployer

    def _infer_target_launch(self):
        """Decide how to launch the target as a subprocess.

        Returns (command, cwd, env, target_script) or None if the repo has no
        recognisable runnable entry point.
          - Python: app.py present -> command=None, target_script=app.py
            (the deployer runs `<python> app.py`).
          - .NET: a *.csproj present -> command=`dotnet run --project <repo>`,
            with ASPNETCORE_URLS pinned to the health_url's origin.
        """
        repo = self.params.repo
        app_py = repo / "app.py"
        if app_py.exists():
            return None, None, None, app_py
        csproj = next(iter(repo.glob("*.csproj")), None)
        if csproj is not None:
            # Pin the app's listen URL to the origin of the health URL so the
            # exploit endpoint and the readiness probe always agree.
            origin = "http://localhost:8080"
            if self.params.health_url:
                from urllib.parse import urlparse
                u = urlparse(self.params.health_url)
                if u.scheme and u.netloc:
                    origin = f"{u.scheme}://{u.netloc}"
            command = [
                "dotnet", "run",
                "--project", str(repo),
                "--no-launch-profile",
                "--verbosity", "quiet",
            ]
            env = {
                "ASPNETCORE_URLS": origin,
                "ASPNETCORE_ENVIRONMENT": "Development",
                "DOTNET_NOLOGO": "1",
                "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
            }
            return command, repo, env, None
        return None

    def _load_imported_findings(self):
        """Return pre-loaded Vulnerability list for import modes, or None."""
        if self.params.mode == "import-sarif" and self.params.sarif_content:
            from orchestrator.importers.sarif_importer import SARIFImporter
            self.emit("scan_start", "Loading SARIF findings…", mode="import-sarif")
            return SARIFImporter(self.params.repo).parse_json(self.params.sarif_content)
        if self.params.mode == "import-checkmarx":
            from orchestrator.importers.checkmarx_connector import CheckmarxConnector
            self.emit("scan_start", "Connecting to Checkmarx One…", mode="import-checkmarx")
            connector = CheckmarxConnector(
                base_url=self.params.checkmarx_url or "",
                tenant=self.params.checkmarx_tenant or "",
                client_id=self.params.checkmarx_client_id or "",
                client_secret=self.params.checkmarx_client_secret or "",
            )
            return connector.fetch_findings(
                scan_id=self.params.checkmarx_scan_id or "",
                repo_root=self.params.repo,
            )
        return None

    def _build_brain(self) -> SecurityBrain:
        # Import modes run the full pipeline (attacker+healer+validator) against
        # externally supplied findings, so they are NOT scan-only.
        scan_only = self.params.mode == "scan-only"
        llm = None if scan_only else self._build_llm()
        runner, deployer = self._build_runner_and_deployer()
        return SecurityBrain(
            repo_root=self.params.repo,
            target_endpoint=self.params.target_endpoint,
            rules_dir=DEFAULT_RULES,
            llm=llm,
            min_severity=self.params.min_severity,
            max_findings_per_run=self.params.max_findings,
            scan_only=scan_only,
            deployer=deployer,
            runner=runner,
            test_command=self.params.test_command,
            on_event=self.emit,
            github_repo_slug=self.params.github_repo_slug,
            github_token=self.params.github_token,
            github_base_branch=self.params.github_base_branch,
        )

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _persist(self) -> None:
        try:
            record = StoredScan(
                scan_id=self.scan_id,
                repo=str(self.params.repo),
                mode=self.params.mode,
                status=self.status,
                started_at=self.started_at,
                finished_at=self.finished_at,
                error=self.error,
                report=self.report.to_dict() if self.report else None,
                findings_index={str(k): v for k, v in self.findings_index.items()},
            )
            self.store.save(record)
        except Exception:
            log.exception("failed to persist scan %s", self.scan_id)

    def _build_efficiency_brain(self):
        """Build the EfficiencyBrain. Mirrors _build_brain() but for the
        efficiency mission. The two brains share the LLM client + runner so
        infrastructure (sandbox, agent SDK) is reused.

        Mode 'efficiency-profile' runs scan-only (profiler emits findings but
        no LLM refactor / sandbox benchmark fire) so the user can test the
        profiler against arbitrary real repos without setup.
        """
        from orchestrator.brain_perf import EfficiencyBrain
        from orchestrator.exploits.subprocess_runner import SubprocessRunner
        from orchestrator.models.perf import SavingsConfig
        rules_dir = ROOT / "orchestrator" / "rules" / "efficiency"
        scan_only = (self.params.mode == "efficiency-profile")
        llm = None if scan_only else self._build_llm()
        runner = None if scan_only else SubprocessRunner()
        savings_config = SavingsConfig.from_request(
            calls_per_year=self.params.calls_per_year,
            cpu_cost_per_hour_usd=self.params.cpu_cost_per_hour_usd,
            grid_region=self.params.grid_region,
            avg_cpu_power_watts=self.params.avg_cpu_power_watts,
        )
        profile_hints = {}
        if self.params.profile_json:
            from orchestrator.profile_import import parse_profile_json
            profile_hints = parse_profile_json(
                self.params.profile_json, total_calls_per_year=self.params.calls_per_year)
            if profile_hints:
                self.emit("scan_start",
                          f"runtime profile imported: {len(profile_hints)} hot function(s)",
                          mode=self.params.mode)
        return EfficiencyBrain(
            repo_root=self.params.repo,
            rules_dir=rules_dir,
            llm=llm,
            runner=runner,
            max_findings_per_run=self.params.max_findings,
            calls_per_year=self.params.calls_per_year,
            savings_config=savings_config,
            on_event=self.emit,
            scan_only=scan_only,
            github_repo_slug=self.params.github_repo_slug,
            github_token=self.params.github_token,
            github_base_branch=self.params.github_base_branch,
            pr_provider=self.params.pr_provider,
            bitbucket_workspace=self.params.bitbucket_workspace,
            bitbucket_repo_slug=self.params.bitbucket_repo_slug,
            bitbucket_token=self.params.bitbucket_token,
            profile_hints=profile_hints,
        )

    def _build_ci_guard(self):
        from orchestrator.ci_guard import CIGuard
        rules_dir = ROOT / "orchestrator" / "rules" / "efficiency"
        return CIGuard(
            repo_root=self.params.repo,
            rules_dir=rules_dir,
            base_ref=self.params.ci_base_ref,
            fail_severity=self.params.ci_fail_severity,
            max_findings=self.params.max_findings,
            on_event=self.emit,
            github_repo_slug=self.params.github_repo_slug,
            github_token=self.params.github_token,
            pr_number=self.params.ci_pr_number,
        )

    def _run(self) -> None:
        self.status = "running"
        self.started_at = self._now()
        try:
            if self.params.mode == "efficiency-ci-guard":
                guard = self._build_ci_guard()
                self.report = guard.run()
            elif self.params.mode in ("efficiency", "efficiency-profile"):
                brain = self._build_efficiency_brain()
                self.report = brain.run_efficiency_loop()
            else:
                brain = self._build_brain()
                imported = self._load_imported_findings()
                self.report = brain.run_security_loop(
                    imported_findings=imported,
                    mode_label=self.params.mode if imported is not None else None,
                )
            self.status = "done"
        except Exception as e:
            log.exception("scan %s failed", self.scan_id)
            self.error = f"{type(e).__name__}: {e}"
            self.status = "error"
            self.emit(SCAN_ERROR, self.error)
            # Always emit a terminal SCAN_DONE so the frontend can close the
            # stream cleanly even on error.
            self.emit(SCAN_DONE, "scan ended with error", error=self.error)
        finally:
            self.finished_at = self._now()
            self._persist()

    def start(self) -> None:
        threading.Thread(target=self._run, name=f"scan-{self.scan_id}", daemon=True).start()


class _AgentSDKWithFallback:
    """Wraps ClaudeAgentSDKClient; on CLIConnectionError swaps to a fallback.

    CLIConnectionError is only raised when the first real LLM call is made,
    not during __init__, so it can't be caught in _build_llm(). This wrapper
    intercepts the error on that first call and retries transparently with the
    fallback (ANTHROPIC_API_KEY or CannedLLM), then stays on the fallback for
    all subsequent calls in the same scan.
    """

    def __init__(self, primary: LLMClient, make_fallback) -> None:
        self._client = primary
        self._make_fallback = make_fallback

    def complete(self, system: str, user: str, **kw):
        try:
            return self._client.complete(system, user, **kw)
        except Exception as exc:
            if self._is_cli_error(exc):
                log.warning(
                    "AgentSDK CLIConnectionError — switching to fallback LLM for this scan"
                )
                self._client = self._make_fallback()
                return self._client.complete(system, user, **kw)
            raise

    def complete_json(self, system: str, user: str, **kw):
        # complete_json is defined on LLMClient base; delegate to avoid duplication.
        try:
            return self._client.complete_json(system, user, **kw)
        except Exception as exc:
            if self._is_cli_error(exc):
                log.warning(
                    "AgentSDK CLIConnectionError — switching to fallback LLM for this scan"
                )
                self._client = self._make_fallback()
                return self._client.complete_json(system, user, **kw)
            raise

    @staticmethod
    def _is_cli_error(exc: Exception) -> bool:
        name = type(exc).__name__
        msg = str(exc)
        return (
            "CLIConnectionError" in name
            or "AuthenticationError" in name
            or "Failed to start Claude Code" in msg
            or "invalid x-api-key" in msg.lower()
            or ("claude" in msg.lower() and "connect" in msg.lower())
        )


class ScanManager:
    def __init__(self, store_dir: Path | None = None) -> None:
        self._scans: dict[str, ScanRunner] = {}
        self.store = ScanStore(store_dir or DEFAULT_STORE)
        # No rehydration into the active runner dict -- finished scans live on
        # disk and get served from there by get_report / get_finding. Anything
        # in self._scans is in-flight or already-served-from-memory.

    def create(self, params: ScanParams) -> ScanRunner:
        scan_id = uuid.uuid4().hex[:12]
        runner = ScanRunner(
            scan_id=scan_id,
            params=params,
            loop=asyncio.get_running_loop(),
            store=self.store,
        )
        self._scans[scan_id] = runner
        runner.start()
        return runner

    def get(self, scan_id: str) -> ScanRunner | None:
        return self._scans.get(scan_id)

    def get_stored(self, scan_id: str) -> StoredScan | None:
        return self.store.load(scan_id)

    def list(self) -> list[dict]:
        seen: set[str] = set()
        out: list[dict] = []
        # In-memory scans first (they're authoritative for in-flight status).
        for r in self._scans.values():
            seen.add(r.scan_id)
            out.append({
                "scan_id": r.scan_id,
                "repo": str(r.params.repo),
                "mode": r.params.mode,
                "status": r.status,
                "findings": (r.report.scanned if r.report else 0),
                "finished_at": r.finished_at,
            })
        # Then anything else on disk.
        for record in self.store.list_all():
            if record.scan_id in seen:
                continue
            out.append({
                "scan_id": record.scan_id,
                "repo": record.repo,
                "mode": record.mode,
                "status": record.status,
                "findings": (record.report or {}).get("scanned", 0) if record.report else 0,
                "finished_at": record.finished_at,
            })
        return out
