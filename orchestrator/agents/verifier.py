"""VerifierAgent — runs each refactor candidate's benchmark, parses the
BENCH_RESULT JSON, picks the fastest candidate that is still correct, and
computes annual $ + gCO₂ (+ memory) savings.

Sibling of ValidatorAgent (security mode). Where the security validator asks
"does the exploit still succeed?", this verifier asks "do the outputs match AND
is the new code actually faster?" — and now, "which of several candidates wins?"

Language-aware (P1):
  * python  -> stage `_refactored.py` beside the original; run the shared
               sibling-import benchmark via the SubprocessRunner.
  * java    -> compile a self-contained `Bench.java` with javac, run with java.
  * dotnet  -> drop a self-contained program in a temp console project, dotnet run.
Java/.NET verification degrades gracefully (status stays REFACTORED with a note)
when the toolchain isn't installed, rather than failing the refactor outright.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..exploits.runner import SandboxResult
from ..models.perf import (
    BenchmarkResult,
    Candidate,
    PerfFinding,
    PerfStatus,
    Savings,
    SavingsConfig,
)
from .base import Agent, AgentContext


log = logging.getLogger("security_brain.verifier")

# Sentinel exit code meaning "the language toolchain isn't available" — the
# refactor is fine, we just can't run the benchmark here.
_TOOLCHAIN_MISSING = -2


class VerifierAgent(Agent):
    name = "verifier"

    def __init__(self, llm, runner, savings_config: SavingsConfig | None = None,
                 calls_per_year: int = 3_600_000):
        super().__init__(llm)
        self.runner = runner             # SubprocessRunner duck-type (python path)
        self.savings_config = savings_config or SavingsConfig(calls_per_year=calls_per_year)

    # ------------------------------------------------------------------
    def run_finding(self, finding: PerfFinding, ctx: AgentContext) -> PerfFinding:
        if finding.refactoring is None:
            finding.notes.append("verifier: no refactoring to verify")
            return finding

        language = (finding.language or "python").lower()
        bench_shared = finding.refactoring.benchmark_script

        # Build the candidate list. Legacy/back-compat path: no explicit
        # candidates -> wrap the single refactoring as one candidate.
        candidates = finding.candidates or [Candidate(
            refactored_code=finding.refactoring.refactored_code,
            explanation=finding.refactoring.explanation,
            confidence=1.0,
            benchmark_program=bench_shared if language != "python" else "",
        )]

        executed_any = False
        toolchain_note = ""
        for cand in candidates:
            bench_text = bench_shared if language == "python" else (
                cand.benchmark_program or bench_shared)
            result = self._run_language_benchmark(
                finding, cand.refactored_code, bench_text, language)
            if result.exit_code == _TOOLCHAIN_MISSING:
                toolchain_note = result.stderr
                break
            executed_any = True
            br = self._parse_bench_result(result.stdout or "")
            if br is None:
                cand.rejected_reason = (
                    "no BENCH_RESULT line; stderr: " + (result.stderr or "")[-200:])
                continue
            br.raw_stdout = (result.stdout or "")[-800:]
            cand.benchmark = br
            if not br.outputs_match:
                cand.rejected_reason = "outputs diverged from original"
            elif br.runtime_ms_new >= br.runtime_ms_old:
                cand.rejected_reason = (
                    f"no speedup (old={br.runtime_ms_old:.2f}ms "
                    f"new={br.runtime_ms_new:.2f}ms)")

        # No benchmark could run because the toolchain is absent -> keep the
        # refactor, mark it unverified.
        if not executed_any and toolchain_note:
            finding.status = PerfStatus.REFACTORED
            finding.notes.append(f"verifier: verification skipped — {toolchain_note}")
            return finding

        # Pick the fastest candidate that is correct AND faster.
        winners = [c for c in candidates
                   if c.benchmark and c.benchmark.outputs_match
                   and c.benchmark.runtime_ms_new < c.benchmark.runtime_ms_old]
        if not winners:
            finding.status = PerfStatus.FAILED
            reason = next((c.rejected_reason for c in candidates if c.rejected_reason),
                          "benchmark produced no usable result")
            # Mirror the legacy note phrasing the UI keys on.
            if "diverged" in reason:
                finding.notes.append(
                    "verifier: refactored function produced DIFFERENT output than original")
            elif "no speedup" in reason:
                finding.notes.append(f"verifier: refactor did NOT improve runtime — {reason}")
            else:
                finding.notes.append(f"verifier: {reason}")
            # Persist what we tried for the report.
            self._record_candidate_trail(finding, candidates)
            return finding

        winners.sort(key=lambda c: c.benchmark.runtime_ms_new)  # type: ignore[union-attr]
        best = winners[0]
        bench_result = best.benchmark
        assert bench_result is not None

        # Promote the winning candidate into the finding's refactoring.
        finding.benchmark = bench_result
        finding.refactoring.refactored_code = best.refactored_code
        finding.refactoring.explanation = best.explanation or finding.refactoring.explanation
        if best.complexity_before:
            finding.refactoring.complexity_before = best.complexity_before
        if best.complexity_after:
            finding.refactoring.complexity_after = best.complexity_after
        # Keep the runner-up for the PR's "alternative" section.
        if len(winners) > 1:
            ru = winners[1]
            finding.refactoring.runner_up_code = ru.refactored_code
            finding.refactoring.runner_up_note = (
                f"alt candidate: {ru.benchmark.speedup_x:.1f}× "  # type: ignore[union-attr]
                f"(confidence {ru.confidence:.2f})")

        # Per-finding call-rate override (P7) wins over the global config.
        cfg = self.savings_config
        if finding.calls_per_year_override:
            from dataclasses import replace
            cfg = replace(cfg, calls_per_year=int(finding.calls_per_year_override))
        finding.savings = Savings.from_config(
            cfg,
            runtime_saved_ms_per_call=bench_result.runtime_saved_ms_per_call,
            memory_saved_kb_per_call=bench_result.memory_saved_kb_per_call,
        )
        finding.status = PerfStatus.VERIFIED
        mem = ""
        if bench_result.memory_saved_kb_per_call > 0:
            mem = f", {bench_result.memory_saved_kb_per_call:,.0f} KB/call less memory"
        picked = (f" (picked best of {len(candidates)} candidates)"
                  if len(candidates) > 1 else "")
        finding.notes.append(
            f"verifier: outputs match AND speedup {bench_result.speedup_x:.1f}×{mem}{picked} — "
            f"projected ${finding.savings.annual_dollars:,.2f}/yr and "
            f"{finding.savings.annual_co2_grams:,.0f} g CO₂/yr saved"
        )
        self._record_candidate_trail(finding, candidates)
        return finding

    @staticmethod
    def _record_candidate_trail(finding: PerfFinding, candidates: list[Candidate]) -> None:
        # If the finding only had the implicit single candidate, don't clutter
        # the report with a redundant trail.
        if finding.candidates:
            finding.candidates = candidates

    def run(self, vuln, ctx):  # pragma: no cover -- interface compat
        raise NotImplementedError("VerifierAgent uses run_finding(PerfFinding, ...)")

    # ------------------------------------------------------------------
    # Language dispatch
    # ------------------------------------------------------------------
    def _run_language_benchmark(self, finding, refactored_code, bench_text, language) -> SandboxResult:
        if not bench_text:
            return SandboxResult(exit_code=1, stdout="", stderr="no benchmark text")
        if language == "java":
            return self._run_java(bench_text)
        if language == "dotnet":
            return self._run_dotnet(bench_text)
        return self._run_python(finding, refactored_code, bench_text)

    def _run_python(self, finding, refactored_code, bench_text) -> SandboxResult:
        target_dir = finding.location.file.parent
        refactored_path = target_dir / "_refactored.py"
        try:
            refactored_path.write_text(refactored_code, encoding="utf-8")
        except OSError as e:
            return SandboxResult(exit_code=1, stdout="", stderr=f"cannot stage _refactored.py: {e}")
        try:
            return self.runner.run_python_exploit(
                script=bench_text, target_url="", timeout_s=60)
        finally:
            try:
                refactored_path.unlink()
            except OSError:
                pass

    def _run_java(self, program: str) -> SandboxResult:
        if shutil.which("javac") is None or shutil.which("java") is None:
            return SandboxResult(_TOOLCHAIN_MISSING, "", "javac/java not found on PATH")
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "Bench.java"
            src.write_text(program, encoding="utf-8")
            try:
                comp = subprocess.run(
                    ["javac", str(src)], cwd=td, capture_output=True, text=True,
                    timeout=120, encoding="utf-8", errors="replace")
            except (subprocess.TimeoutExpired, OSError) as e:
                return SandboxResult(1, "", f"javac failed: {e}")
            if comp.returncode != 0:
                return SandboxResult(1, "", f"javac error: {comp.stderr[-400:]}")
            try:
                run = subprocess.run(
                    ["java", "-cp", td, "Bench"], cwd=td, capture_output=True,
                    text=True, timeout=60, encoding="utf-8", errors="replace")
            except (subprocess.TimeoutExpired, OSError) as e:
                return SandboxResult(1, "", f"java run failed: {e}")
            return SandboxResult(run.returncode, run.stdout, run.stderr)

    def _run_dotnet(self, program: str) -> SandboxResult:
        if shutil.which("dotnet") is None:
            return SandboxResult(_TOOLCHAIN_MISSING, "", "dotnet SDK not found on PATH")
        tfm = self._dotnet_tfm()
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td)
            (proj / "Program.cs").write_text(program, encoding="utf-8")
            (proj / "bench.csproj").write_text(
                "<Project Sdk=\"Microsoft.NET.Sdk\">\n"
                "  <PropertyGroup>\n"
                "    <OutputType>Exe</OutputType>\n"
                f"    <TargetFramework>{tfm}</TargetFramework>\n"
                "    <Nullable>disable</Nullable>\n"
                "    <ImplicitUsings>enable</ImplicitUsings>\n"
                "    <AssemblyName>bench</AssemblyName>\n"
                "  </PropertyGroup>\n"
                "</Project>\n",
                encoding="utf-8")
            env = {**os.environ, "DOTNET_NOLOGO": "1", "DOTNET_CLI_TELEMETRY_OPTOUT": "1"}
            try:
                run = subprocess.run(
                    ["dotnet", "run", "--project", str(proj), "-c", "Release",
                     "--verbosity", "quiet"],
                    cwd=td, capture_output=True, text=True, timeout=240,
                    env=env, encoding="utf-8", errors="replace")
            except (subprocess.TimeoutExpired, OSError) as e:
                return SandboxResult(1, "", f"dotnet run failed: {e}")
            return SandboxResult(run.returncode, run.stdout, run.stderr)

    @staticmethod
    def _dotnet_tfm() -> str:
        """Best guess at a target framework matching the installed SDK."""
        try:
            r = subprocess.run(["dotnet", "--version"], capture_output=True,
                               text=True, timeout=10)
            major = r.stdout.strip().split(".")[0]
            if major.isdigit() and int(major) >= 6:
                return f"net{major}.0"
        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass
        return "net8.0"

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_bench_result(stdout: str) -> BenchmarkResult | None:
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("BENCH_RESULT:"):
                try:
                    payload = json.loads(line[len("BENCH_RESULT:"):].strip())
                except json.JSONDecodeError:
                    continue
                return BenchmarkResult(
                    runtime_ms_old=float(payload.get("runtime_ms_old", 0.0)),
                    runtime_ms_new=float(payload.get("runtime_ms_new", 0.0)),
                    iterations=int(payload.get("iterations", 0)),
                    memory_kb_old=_opt_float(payload.get("memory_kb_old")),
                    memory_kb_new=_opt_float(payload.get("memory_kb_new")),
                    outputs_match=bool(payload.get("outputs_match", False)),
                    inputs_description=str(payload.get("inputs_description", "")),
                )
            if line.startswith("BENCH_FAIL:"):
                return BenchmarkResult(
                    outputs_match=False,
                    inputs_description=line[len("BENCH_FAIL:"):].strip(),
                )
        return None


def _opt_float(v) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None
