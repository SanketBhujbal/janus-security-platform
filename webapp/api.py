"""FastAPI app for the Agentic Security Platform UI.

Endpoints:
  GET  /                         -> single-page UI
  POST /api/scans                -> start a scan, returns {scan_id}
  GET  /api/scans                -> list scans
  GET  /api/scans/{id}           -> scan summary + status
  GET  /api/scans/{id}/events    -> SSE stream of progress events
  GET  /api/scans/{id}/report    -> final report (after scan done)
  GET  /api/scans/{id}/findings/{idx} -> finding detail (snippet, exploit, patch)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from orchestrator.models.vulnerability import Severity

from .manager import ScanManager, ScanParams


log = logging.getLogger("webapp")

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"

manager: ScanManager | None = None


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    global manager
    manager = ScanManager()
    log.info("scan manager ready")
    yield


app = FastAPI(title="Agentic Security Platform", lifespan=_lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


def _mgr() -> ScanManager:
    assert manager is not None, "scan manager not initialized"
    return manager


class StartScanRequest(BaseModel):
    repo: str = Field(..., description="absolute path to the repo to scan")
    mode: str = Field(
        "scan-only",
        pattern="^(scan-only|full|efficiency|efficiency-profile|efficiency-ci-guard)$")
    min_severity: str = Field("medium")
    max_findings: int = Field(200, ge=1, le=1000)
    target_endpoint: str | None = None
    compose_file: str | None = None
    compose_service: str | None = None
    health_url: str | None = None
    # Optional GitHub PR integration: "owner/repo" — if set, a PR is raised
    # automatically after validated (security) or verified (efficiency) findings.
    github_repo_slug: str | None = None
    github_token: str | None = None
    github_base_branch: str = "main"
    # --- Efficiency savings assumptions (P2) ---
    calls_per_year: int = 3_600_000
    cpu_cost_per_hour_usd: float | None = None
    grid_region: str | None = None
    avg_cpu_power_watts: float | None = None
    # --- Runtime profile import (P7) ---
    profile_json: str | None = None
    # --- Bitbucket PR backend (P6) ---
    pr_provider: str = Field("github", pattern="^(github|bitbucket)$")
    bitbucket_workspace: str | None = None
    bitbucket_repo_slug: str | None = None
    bitbucket_token: str | None = None
    # --- CI guard mode (P5) ---
    ci_base_ref: str = "origin/main"
    ci_fail_severity: str = "high"
    ci_pr_number: int | None = None

    @field_validator("min_severity", "ci_fail_severity")
    @classmethod
    def _valid_severity(cls, v: str) -> str:
        try:
            Severity(v)
        except ValueError:
            raise ValueError(f"unknown severity {v}")
        return v


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse((STATIC / "index.html").read_text(encoding="utf-8"))


@app.post("/api/scans")
async def start_scan(req: StartScanRequest) -> dict[str, Any]:
    repo = Path(req.repo).expanduser()
    if not repo.exists():
        raise HTTPException(400, f"repo path does not exist: {repo}")
    if not repo.is_dir():
        raise HTTPException(400, f"repo path is not a directory: {repo}")
    params = ScanParams(
        repo=repo.resolve(),
        mode=req.mode,
        min_severity=Severity(req.min_severity),
        max_findings=req.max_findings,
        target_endpoint=req.target_endpoint,
        compose_file=Path(req.compose_file).resolve() if req.compose_file else None,
        compose_service=req.compose_service,
        health_url=req.health_url,
        github_repo_slug=req.github_repo_slug or None,
        github_token=req.github_token or None,
        github_base_branch=req.github_base_branch,
        calls_per_year=req.calls_per_year,
        cpu_cost_per_hour_usd=req.cpu_cost_per_hour_usd,
        grid_region=req.grid_region,
        avg_cpu_power_watts=req.avg_cpu_power_watts,
        profile_json=req.profile_json or None,
        pr_provider=req.pr_provider,
        bitbucket_workspace=req.bitbucket_workspace or None,
        bitbucket_repo_slug=req.bitbucket_repo_slug or None,
        bitbucket_token=req.bitbucket_token or None,
        ci_base_ref=req.ci_base_ref,
        ci_fail_severity=Severity(req.ci_fail_severity),
        ci_pr_number=req.ci_pr_number,
    )
    runner = _mgr().create(params)
    return {"scan_id": runner.scan_id, "status": runner.status}


@app.post("/api/scans/demo-efficiency")
async def start_efficiency_demo() -> dict[str, Any]:
    """One-click efficiency demo — profile → refactor → verify → savings.

    Uses the purpose-built janus-demo-efficiency repo (payment_processor.py)
    with 4 patterns sized for 100-300× speedups and impressive $/yr numbers.
    Falls back to the internal sandbox/target-perf if the repo isn't cloned.
    """
    # Primary: dedicated demo repo with business-contextual function names
    primary = Path(r"C:\Users\bhujbalsa\janus-demo-efficiency")
    # Fallback: original internal seeded target
    fallback = Path(__file__).resolve().parents[1] / "sandbox" / "target-perf"

    if primary.exists() and (primary / "payment_processor.py").exists():
        target_src = primary
    elif fallback.exists():
        target_src = fallback
    else:
        raise HTTPException(500, "efficiency demo target missing")

    params = ScanParams(
        repo=target_src,
        mode="efficiency",
        min_severity=Severity.MEDIUM,
        max_findings=3,       # verified | verified | failed
        max_candidates=2,     # 2 LLM variants per finding = ~35% faster than 3
        # Impressive demo savings: 500M calls/yr at c6g.2xlarge price, EU grid
        calls_per_year=500_000_000,
        cpu_cost_per_hour_usd=0.272,
        grid_region="eu",
    )
    runner = _mgr().create(params)
    return {
        "scan_id": runner.scan_id,
        "status": runner.status,
        "mode": "demo-efficiency",
        "target": str(target_src),
    }


@app.post("/api/scans/demo")
async def start_demo_scan() -> dict[str, Any]:
    # One-click full-loop demo against the seeded vulnerable Python target.
    # Docker is preferred but if it's not installed the manager falls back to
    # a subprocess deployer that runs Flask on localhost. In that case the
    # exploit URL needs to be localhost, not the compose-network DNS name.
    import shutil
    import subprocess
    root = Path(__file__).resolve().parents[1]
    target_src = root / "sandbox" / "target-api"
    compose_file = root / "sandbox" / "docker-compose.yml"
    if not target_src.exists() or not compose_file.exists():
        raise HTTPException(500, "seeded target or compose file missing")

    # Reset the seeded app.py from .original so each demo run starts from the
    # canonical vulnerable state. Without this, every healer-applied patch
    # would compound across runs and shift the seeded vulnerabilities into
    # different line numbers or remove them entirely.
    original = target_src / "app.py.original"
    live = target_src / "app.py"
    if original.exists():
        shutil.copyfile(original, live)
        log.info("demo: restored %s from .original", live.name)

    docker_ok = shutil.which("docker") is not None
    if docker_ok:
        try:
            r = subprocess.run(["docker", "info"], capture_output=True, timeout=3)
            docker_ok = r.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            docker_ok = False

    if docker_ok:
        target_url = "http://target-api:8080"
        health = "http://localhost:8080/health"
    else:
        target_url = "http://localhost:8080"
        health = "http://localhost:8080/health"

    params = ScanParams(
        repo=target_src,
        mode="full",
        min_severity=Severity.MEDIUM,
        max_findings=10,
        target_endpoint=target_url,
        compose_file=compose_file if docker_ok else None,
        compose_service="target-api" if docker_ok else None,
        health_url=health,
    )
    runner = _mgr().create(params)
    return {
        "scan_id": runner.scan_id,
        "status": runner.status,
        "mode": "demo-full-loop",
        "backend": "docker" if docker_ok else "subprocess",
    }


class DotnetDemoRequest(BaseModel):
    github_repo_slug: str | None = None
    github_token: str | None = None
    github_base_branch: str = "main"


@app.post("/api/scans/demo-security")
async def start_security_demo() -> dict[str, Any]:
    """One-click security demo — exploit → patch → validate.

    Uses the purpose-built janus-demo-security repo. Resets app.py from
    .original before each run so the demo always starts from the clean
    vulnerable baseline. Falls back to sandbox/target-api if repo not cloned.
    """
    import shutil
    # Primary: dedicated demo repo
    primary = Path(r"C:\Users\bhujbalsa\janus-demo-security")
    # Fallback: original internal sandbox
    root = Path(__file__).resolve().parents[1]
    fallback = root / "sandbox" / "target-api"

    if primary.exists() and (primary / "app.py").exists():
        target_src = primary
    elif fallback.exists():
        target_src = fallback
    else:
        raise HTTPException(500, "security demo target missing")

    # Reset app.py from .original so each run starts from the canonical
    # vulnerable state (healer patches accumulate across runs otherwise).
    original = target_src / "app.py.original"
    live = target_src / "app.py"
    if original.exists():
        shutil.copyfile(original, live)
        log.info("security demo: restored app.py from .original in %s", target_src)

    params = ScanParams(
        repo=target_src,
        mode="full",
        min_severity=Severity.HIGH,    # HIGH only = 1-2 findings = fast demo
        max_findings=2,
        target_endpoint="http://localhost:8080",
        health_url="http://localhost:8080/health",
    )
    runner = _mgr().create(params)
    return {
        "scan_id": runner.scan_id,
        "status": runner.status,
        "mode": "demo-security",
        "target": str(target_src),
    }


@app.post("/api/scans/demo-dotnet")
async def start_demo_dotnet_scan(req: DotnetDemoRequest = DotnetDemoRequest()) -> dict[str, Any]:
    # One-click full-loop demo against the seeded vulnerable ASP.NET Core target.
    # Optionally accepts github_repo_slug + github_token to auto-open a PR after
    # validated findings are committed to the GitHub repo.
    import shutil
    root = Path(__file__).resolve().parents[1]
    target_src = root / "sandbox" / "target-dotnet-api"
    if not (target_src / "target-dotnet-api.csproj").exists():
        raise HTTPException(500, "seeded .NET target missing")
    if shutil.which("dotnet") is None:
        raise HTTPException(500, "dotnet SDK not found on PATH — cannot run the .NET demo")

    # Reset Program.cs from .original so each run starts from the canonical
    # vulnerable state (otherwise prior patches compound across runs).
    original = target_src / "Program.cs.original"
    live = target_src / "Program.cs"
    if original.exists():
        shutil.copyfile(original, live)
        log.info("demo-dotnet: restored %s from .original", live.name)

    params = ScanParams(
        repo=target_src,
        mode="full",
        min_severity=Severity.MEDIUM,
        max_findings=10,
        target_endpoint="http://localhost:8080",
        health_url="http://localhost:8080/health",
        test_command=["dotnet", "--version"],
        github_repo_slug=req.github_repo_slug or None,
        github_token=req.github_token or os.environ.get("GITHUB_TOKEN") or None,
        github_base_branch=req.github_base_branch,
    )
    runner = _mgr().create(params)
    pr_enabled = bool(params.github_repo_slug and params.github_token)
    return {
        "scan_id": runner.scan_id,
        "status": runner.status,
        "mode": "demo-dotnet-full-loop",
        "backend": "subprocess-dotnet",
        "pr_enabled": pr_enabled,
    }


@app.get("/api/scans")
async def list_scans() -> list[dict[str, Any]]:
    return _mgr().list()


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict[str, Any]:
    runner = _mgr().get(scan_id)
    if runner is not None:
        return {
            "scan_id": runner.scan_id,
            "status": runner.status,
            "error": runner.error,
            "repo": str(runner.params.repo),
            "mode": runner.params.mode,
            "summary": runner.report.to_dict() if runner.report else None,
        }
    stored = _mgr().get_stored(scan_id)
    if stored is None:
        raise HTTPException(404, "scan not found")
    return {
        "scan_id": stored.scan_id,
        "status": stored.status,
        "error": stored.error,
        "repo": stored.repo,
        "mode": stored.mode,
        "summary": stored.report,
    }


@app.get("/api/scans/{scan_id}/events")
async def stream_events(scan_id: str, request: Request) -> StreamingResponse:
    runner = _mgr().get(scan_id)
    if runner is None:
        raise HTTPException(404, "scan not found")

    async def gen():
        # Send an initial hello so EventSource fires `open`.
        yield "event: open\ndata: {}\n\n"
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(runner.queue.get(), timeout=15)
            except asyncio.TimeoutError:
                # Keep the connection alive through proxies that close idle streams.
                yield ": keepalive\n\n"
                continue
            yield f"data: {json.dumps(event)}\n\n"
            if event.get("type") == "scan_done":
                break

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/scans/{scan_id}/report")
async def get_report(scan_id: str, download: bool = True) -> JSONResponse:
    runner = _mgr().get(scan_id)
    report: dict | None = None
    if runner is not None and runner.report is not None:
        report = runner.report.to_dict()
    if report is None:
        stored = _mgr().get_stored(scan_id)
        if stored is None:
            raise HTTPException(404, "scan not found")
        if stored.report is None:
            raise HTTPException(409, f"report not ready (status={stored.status})")
        report = stored.report
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="report-{scan_id}.json"'
    return JSONResponse(content=report, headers=headers)


@app.get("/api/scans/{scan_id}/compliance")
async def get_compliance_report(scan_id: str, format: str = "json") -> Any:
    """Return the compliance mapping for a completed scan.

    ?format=html  →  self-contained HTML report (for browser / email)
    ?format=json  →  machine-readable compliance dict (default)
    """
    # Resolve the repo path from the scan so we can find .security_workdir
    runner = _mgr().get(scan_id)
    repo: Path | None = None
    if runner is not None:
        repo = runner.params.repo
    if repo is None:
        stored = _mgr().get_stored(scan_id)
        if stored is not None and stored.repo:
            repo = Path(stored.repo)
    if repo is None:
        raise HTTPException(404, "scan not found")

    workdir = repo / ".security_workdir"

    report_path = workdir / "report.json"
    if not report_path.exists():
        raise HTTPException(409, "report not ready yet — scan may still be running")

    report_data = json.loads(report_path.read_text(encoding="utf-8"))

    if format == "html":
        html_path = workdir / "compliance_report.html"
        if html_path.exists():
            return Response(
                content=html_path.read_text(encoding="utf-8"),
                media_type="text/html",
                headers={"Content-Disposition": f'attachment; filename="compliance-{scan_id}.html"'},
            )
        # File not pre-generated — build it on the fly from report.json.
        try:
            from orchestrator.report.compliance import ComplianceReporter
            html_content = ComplianceReporter()._render(report_data)
            return Response(
                content=html_content,
                media_type="text/html",
                headers={"Content-Disposition": f'attachment; filename="compliance-{scan_id}.html"'},
            )
        except Exception as e:
            raise HTTPException(500, f"compliance HTML generation failed: {e}")

    # JSON format (default)
    json_path = workdir / "compliance.json"
    if json_path.exists():
        return JSONResponse(content=json.loads(json_path.read_text(encoding="utf-8")))

    try:
        from orchestrator.report.compliance import ComplianceReporter
        return JSONResponse(content=ComplianceReporter().generate_dict(report_data))
    except Exception as e:
        raise HTTPException(500, f"compliance generation failed: {e}")


@app.get("/api/scans/{scan_id}/findings/{idx}")
async def get_finding(scan_id: str, idx: int) -> dict[str, Any]:
    runner = _mgr().get(scan_id)
    if runner is not None:
        if runner.report is not None:
            findings = runner.report.to_dict().get("findings", [])
            if 0 <= idx < len(findings):
                return findings[idx]
        if idx in runner.findings_index:
            return {**runner.findings_index[idx], "_partial": True}
    stored = _mgr().get_stored(scan_id)
    if stored is not None and stored.report is not None:
        findings = stored.report.get("findings", [])
        if 0 <= idx < len(findings):
            return findings[idx]
    raise HTTPException(404, f"finding {idx} not found")


class CheckmarxImportRequest(BaseModel):
    repo: str = Field(..., description="Local path to the repo the scan was run against")
    checkmarx_url: str = Field(..., description="Checkmarx One base URL, e.g. https://eu.checkmarx.net")
    checkmarx_tenant: str = Field(..., description="Checkmarx One tenant name")
    client_id: str = Field(..., description="OAuth2 client_id")
    client_secret: str = Field(..., description="OAuth2 client_secret")
    scan_id: str = Field(..., description="UUID of the Checkmarx scan to import")
    min_severity: str = Field("medium")
    max_findings: int = Field(200, ge=1, le=1000)
    target_endpoint: str | None = None
    github_repo_slug: str | None = None
    github_token: str | None = None
    github_base_branch: str = "main"

    @field_validator("min_severity")
    @classmethod
    def _valid_severity(cls, v: str) -> str:
        try:
            Severity(v)
        except ValueError:
            raise ValueError(f"unknown severity {v}")
        return v


@app.post("/api/import/sarif")
async def import_sarif(
    sarif_file: UploadFile,
    repo: str = Form(...),
    min_severity: str = Form("medium"),
    max_findings: int = Form(200),
    target_endpoint: str | None = Form(None),
    github_repo_slug: str | None = Form(None),
    github_token: str | None = Form(None),
    github_base_branch: str = Form("main"),
) -> dict:
    """Upload a SARIF file from any scanner and run the exploit→patch→validate pipeline."""
    repo_path = Path(repo).expanduser()
    if not repo_path.exists():
        raise HTTPException(400, f"repo path does not exist: {repo_path}")
    if not repo_path.is_dir():
        raise HTTPException(400, f"repo path is not a directory: {repo_path}")
    try:
        content = (await sarif_file.read()).decode("utf-8")
    except Exception as e:
        raise HTTPException(400, f"Could not read SARIF file: {e}")
    try:
        Severity(min_severity)
    except ValueError:
        raise HTTPException(400, f"unknown severity: {min_severity}")

    params = ScanParams(
        repo=repo_path.resolve(),
        mode="import-sarif",
        min_severity=Severity(min_severity),
        max_findings=max_findings,
        target_endpoint=target_endpoint or None,
        github_repo_slug=github_repo_slug or None,
        github_token=github_token or None,
        github_base_branch=github_base_branch,
        sarif_content=content,
    )
    runner = _mgr().create(params)
    return {"scan_id": runner.scan_id, "status": runner.status, "mode": "import-sarif"}


@app.post("/api/import/checkmarx")
async def import_checkmarx(req: CheckmarxImportRequest) -> dict:
    """Connect to Checkmarx One, pull findings for a scan, then exploit→patch→validate."""
    repo_path = Path(req.repo).expanduser()
    if not repo_path.exists():
        raise HTTPException(400, f"repo path does not exist: {repo_path}")
    if not repo_path.is_dir():
        raise HTTPException(400, f"repo path is not a directory: {repo_path}")

    params = ScanParams(
        repo=repo_path.resolve(),
        mode="import-checkmarx",
        min_severity=Severity(req.min_severity),
        max_findings=req.max_findings,
        target_endpoint=req.target_endpoint or None,
        github_repo_slug=req.github_repo_slug or None,
        github_token=req.github_token or None,
        github_base_branch=req.github_base_branch,
        checkmarx_url=req.checkmarx_url,
        checkmarx_tenant=req.checkmarx_tenant,
        checkmarx_client_id=req.client_id,
        checkmarx_client_secret=req.client_secret,
        checkmarx_scan_id=req.scan_id,
    )
    runner = _mgr().create(params)
    return {"scan_id": runner.scan_id, "status": runner.status, "mode": "import-checkmarx"}


@app.post("/api/scans/demo-security-dotnet")
async def start_security_dotnet_demo() -> dict[str, Any]:
    """One-click .NET security demo — exploit → patch → validate on ASP.NET Core target.
    4 findings: 3 VALIDATED + 1 FAILED (idempotency patch breaks existing test).
    """
    import shutil
    primary  = Path(r"C:\Users\bhujbalsa\janus-demo-security-dotnet")
    fallback = Path(__file__).resolve().parents[1] / "sandbox" / "target-dotnet-api"

    if primary.exists() and (primary / "janus-demo-security-dotnet.csproj").exists():
        target_src = primary
        csproj_name = "janus-demo-security-dotnet.csproj"
    elif fallback.exists():
        target_src = fallback
        csproj_name = "target-dotnet-api.csproj"
    else:
        raise HTTPException(500, ".NET security demo target missing")

    if shutil.which("dotnet") is None:
        raise HTTPException(500, "dotnet SDK not found on PATH")

    original = target_src / "Program.cs.original"
    live     = target_src / "Program.cs"
    if original.exists():
        import shutil as sh; sh.copyfile(original, live)
        log.info("dotnet security demo: restored Program.cs from .original in %s", target_src)

    origin = "http://localhost:8080"
    params = ScanParams(
        repo=target_src,
        mode="full",
        min_severity=Severity.MEDIUM,
        max_findings=4,
        target_endpoint=origin,
        health_url=f"{origin}/health",
        test_command=["pytest", "tests/", "-q", "--tb=short"],
    )
    runner = _mgr().create(params)
    return {"scan_id": runner.scan_id, "status": runner.status,
            "mode": "demo-security-dotnet", "target": str(target_src)}


@app.post("/api/scans/demo-efficiency-dotnet")
async def start_efficiency_dotnet_demo() -> dict[str, Any]:
    """One-click .NET efficiency demo — profile → refactor → verify → savings.
    3 findings: 2 VERIFIED + 1 FAILED (no measurable speedup on small collection).
    """
    import shutil
    primary  = Path(r"C:\Users\bhujbalsa\janus-demo-efficiency-dotnet")
    fallback = Path(__file__).resolve().parents[1] / "sandbox" / "target-perf-dotnet"

    if primary.exists() and (primary / "PaymentProcessor.cs").exists():
        target_src = primary
    elif fallback.exists():
        target_src = fallback
    else:
        raise HTTPException(500, ".NET efficiency demo target missing")

    if shutil.which("dotnet") is None:
        raise HTTPException(500, "dotnet SDK not found on PATH")

    params = ScanParams(
        repo=target_src,
        mode="efficiency",
        min_severity=Severity.MEDIUM,
        max_findings=3,
        max_candidates=2,
        calls_per_year=500_000_000,
        cpu_cost_per_hour_usd=0.272,
        grid_region="eu",
    )
    runner = _mgr().create(params)
    return {"scan_id": runner.scan_id, "status": runner.status,
            "mode": "demo-efficiency-dotnet", "target": str(target_src)}


@app.get("/api/efficiency/savings-presets")
async def savings_presets() -> dict[str, Any]:
    """Grid-intensity presets + default assumptions for the savings config UI (P2)."""
    from orchestrator.models.perf import GRID_INTENSITY_PRESETS, SavingsConfig
    d = SavingsConfig()
    return {
        "grid_presets": GRID_INTENSITY_PRESETS,
        "defaults": {
            "calls_per_year": d.calls_per_year,
            "cpu_cost_per_hour_usd": d.cpu_cost_per_hour_usd,
            "avg_cpu_power_watts": d.avg_cpu_power_watts,
            "grid_region": d.grid_region,
        },
    }


@app.get("/api/efficiency/history")
async def efficiency_history(repo: str) -> dict[str, Any]:
    """Cumulative verified-savings ledger for a repo (P8). Powers the lifetime
    savings KPI + by-category breakdown."""
    repo_path = Path(repo).expanduser()
    if not repo_path.exists():
        raise HTTPException(400, f"repo path does not exist: {repo_path}")
    from orchestrator.perf_history import PerfHistory
    return PerfHistory(repo_path.resolve()).as_dict()


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
