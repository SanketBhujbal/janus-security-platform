"""End-to-end demo of the Agentic Security Platform.

Usage:
    python -m scripts.demo                 # bring up sandbox, run loop, tear down
    python -m scripts.demo --keep          # leave the target-api running afterwards
    python -m scripts.demo --offline       # force canned LLM even if API key is set
    python -m scripts.demo --teardown-only # just tear the sandbox down

Modes:
- ONLINE  (ANTHROPIC_API_KEY set, default): runs the full SecurityBrain loop
  scan -> attack -> patch -> validate -> report.
- OFFLINE (no key, or --offline): runs scan + attacker phase with canned
  exploits keyed by category, then prints the report. Healing is skipped
  because patches require a real model.
"""
from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orchestrator.agents.attacker import AttackerAgent
from orchestrator.agents.base import AgentContext
from orchestrator.exploits.runner import SandboxRunner
from orchestrator.llm.canned import CannedLLM
from orchestrator.llm.claude_client import LLMClient
from orchestrator.models.vulnerability import FindingStatus, Severity, Vulnerability
from orchestrator.orchestrator import SecurityBrain
from orchestrator.sandbox.target_deployer import ComposeTargetDeployer
from orchestrator.scanners.semgrep_scanner import SemgrepScanner


log = logging.getLogger("demo")

COMPOSE_FILE = ROOT / "sandbox" / "docker-compose.yml"
RULES_DIR = ROOT / "orchestrator" / "rules" / "payments"
TARGET_SRC = ROOT / "sandbox" / "target-api"
HEALTH_URL = "http://localhost:8080/health"
TARGET_URL_HOST = "http://localhost:8080"   # host -> container (port published)
TARGET_URL_NET = "http://target-api:8080"   # container -> container (compose network)


# ---------- terminal helpers --------------------------------------------------

class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"


def banner(msg: str) -> None:
    bar = "=" * max(60, len(msg) + 4)
    print(f"\n{C.BOLD}{C.CYAN}{bar}\n  {msg}\n{bar}{C.END}")


def ok(msg: str) -> None:
    print(f"{C.GREEN}[ok]{C.END} {msg}")


def warn(msg: str) -> None:
    print(f"{C.YELLOW}[warn]{C.END} {msg}")


def fail(msg: str) -> None:
    print(f"{C.RED}[fail]{C.END} {msg}")


# ---------- docker plumbing ---------------------------------------------------

def _ensure_docker() -> None:
    if shutil.which("docker") is None:
        fail("docker not found on PATH. Install Docker Desktop first.")
        sys.exit(2)
    rc = subprocess.run(["docker", "info"], capture_output=True).returncode
    if rc != 0:
        fail("docker daemon is not reachable. Start Docker Desktop and re-run.")
        sys.exit(2)


def _compose(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
        capture_output=True, text=True, check=False,
    )


def bring_up_sandbox() -> None:
    banner("1. Building sandbox images")
    r = _compose(["--profile", "build-only", "build", "attacker-image-builder"])
    if r.returncode != 0:
        fail(f"attacker image build failed:\n{r.stderr}")
        sys.exit(1)
    ok("attacker image built")

    r = _compose(["up", "-d", "--build", "target-api"])
    if r.returncode != 0:
        fail(f"target-api start failed:\n{r.stderr}")
        sys.exit(1)
    ok("target-api container started")

    banner("2. Waiting for target-api to become healthy")
    if not _wait_for(HEALTH_URL, timeout_s=60):
        fail(f"target-api never became healthy at {HEALTH_URL}")
        _compose(["logs", "target-api"])
        sys.exit(1)
    ok(f"target-api healthy @ {HEALTH_URL}")


def tear_down() -> None:
    banner("Tearing down sandbox")
    r = _compose(["down", "--remove-orphans"])
    if r.returncode == 0:
        ok("sandbox torn down")
    else:
        warn(f"teardown returned rc={r.returncode}: {r.stderr.strip()}")


def _wait_for(url: str, timeout_s: int) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if 200 <= resp.status < 300:
                    return True
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionError):
            pass
        time.sleep(1)
    return False


# ---------- LLM mode selection ------------------------------------------------

def pick_llm(force_offline: bool) -> tuple[LLMClient, str]:
    if force_offline or not os.environ.get("ANTHROPIC_API_KEY"):
        return CannedLLM(), "offline"
    try:
        from orchestrator.llm.claude_client import ClaudeClient
        return ClaudeClient(), "online"
    except Exception as e:
        warn(f"could not init Claude client: {e}. Falling back to offline mode.")
        return CannedLLM(), "offline"


# ---------- attacker-only loop (offline mode) ---------------------------------

def run_offline_loop(llm: LLMClient) -> list[Vulnerability]:
    scanner = SemgrepScanner(rules_dir=RULES_DIR)
    findings = scanner.scan(TARGET_SRC)
    print(f"\n{C.BOLD}Findings:{C.END} {len(findings)}")
    for f in findings:
        print(
            f"  - {C.YELLOW}{f.category.value:<28}{C.END} "
            f"{f.severity.value:<8} {f.location.as_pointer()}  "
            f"{C.DIM}{f.rule_id}{C.END}"
        )
    if not findings:
        warn("no findings from semgrep — nothing to exploit.")
        return []

    banner("3. Running canned exploits in attacker sandbox")
    sandbox = SandboxRunner()
    agent = AttackerAgent(llm, sandbox)
    ctx = AgentContext(repo_root=ROOT, target_endpoint=TARGET_URL_NET)

    seen_categories: set[str] = set()
    results: list[Vulnerability] = []
    for v in findings:
        # One exploit per category is enough for a demo; the canned exploits
        # are category-keyed.
        if v.category.value in seen_categories:
            v.notes.append("demo: skipped (already exploited this category)")
            results.append(v)
            continue
        seen_categories.add(v.category.value)
        try:
            v = agent.run(v, ctx)
        except RuntimeError as e:
            v.notes.append(f"demo: attacker skipped ({e})")
        results.append(v)
        verdict = (
            f"{C.GREEN}EXPLOITED{C.END}"
            if v.status == FindingStatus.EXPLOITED
            else f"{C.DIM}did not reproduce{C.END}"
        )
        print(f"  - {v.category.value:<28} -> {verdict}")
        if v.exploit and v.exploit.actual_signal:
            print(f"      {C.DIM}signal: {v.exploit.actual_signal[:120]}{C.END}")
    return results


# ---------- full loop (online mode) -------------------------------------------

def run_online_loop(llm: LLMClient) -> list[Vulnerability]:
    deployer = ComposeTargetDeployer(
        compose_file=COMPOSE_FILE,
        service="target-api",
        health_url=HEALTH_URL,
    )
    brain = SecurityBrain(
        repo_root=ROOT,
        target_endpoint=TARGET_URL_NET,
        rules_dir=RULES_DIR,
        llm=llm,
        min_severity=Severity.MEDIUM,
        deployer=deployer,
    )
    banner("3. Running full attack -> patch -> validate loop")
    report = brain.run_security_loop()
    print(
        f"\nscanned={report.scanned}  exploited={report.exploited}  "
        f"patched={report.patched}  validated={C.GREEN}{report.validated}{C.END}  "
        f"failed={C.RED}{report.failed}{C.END}"
    )
    return report.vulnerabilities


# ---------- summary -----------------------------------------------------------

def print_summary(results: list[Vulnerability], mode: str) -> None:
    banner("4. Summary")
    exploited = sum(1 for v in results if v.exploit and v.exploit.succeeded)
    patched = sum(1 for v in results if v.patch is not None)
    validated = sum(1 for v in results if v.status == FindingStatus.VALIDATED)
    print(f"  mode:      {C.BOLD}{mode}{C.END}")
    print(f"  findings:  {len(results)}")
    print(f"  exploited: {C.GREEN if exploited else C.DIM}{exploited}{C.END}")
    print(f"  patched:   {C.GREEN if patched else C.DIM}{patched}{C.END}")
    print(f"  validated: {C.GREEN if validated else C.DIM}{validated}{C.END}")
    if mode == "offline":
        print(
            f"\n  {C.DIM}Healing/validation are skipped in offline mode. "
            f"Set ANTHROPIC_API_KEY to run the full loop.{C.END}"
        )


# ---------- main --------------------------------------------------------------

def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--keep", action="store_true", help="leave the sandbox running after the demo")
    parser.add_argument("--offline", action="store_true", help="force canned LLM even when API key is set")
    parser.add_argument("--teardown-only", action="store_true", help="just stop containers and exit")
    args = parser.parse_args()

    _ensure_docker()

    if args.teardown_only:
        tear_down()
        return 0

    try:
        bring_up_sandbox()
        llm, mode = pick_llm(force_offline=args.offline)
        banner(f"Mode: {mode.upper()}")
        if mode == "online":
            results = run_online_loop(llm)
        else:
            results = run_offline_loop(llm)
        print_summary(results, mode)
        return 0
    except KeyboardInterrupt:
        warn("interrupted")
        return 130
    finally:
        if not args.keep:
            tear_down()
        else:
            print(f"\n{C.DIM}--keep set: target-api still running. "
                  f"Run `python -m scripts.demo --teardown-only` to stop it.{C.END}")


if __name__ == "__main__":
    sys.exit(main())
