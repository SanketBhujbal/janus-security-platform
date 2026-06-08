"""Unit tests for the efficiency mission."""
from __future__ import annotations

from pathlib import Path

from orchestrator.agents.refactor import RefactorAgent
from orchestrator.agents.verifier import VerifierAgent
from orchestrator.agents.base import AgentContext
from orchestrator.exploits.runner import SandboxResult
from orchestrator.models.perf import (
    BenchmarkResult,
    PerfCategory,
    PerfFinding,
    PerfStatus,
    Refactoring,
    Savings,
)
from orchestrator.models.vulnerability import CodeLocation, Severity

from .fakes import FakeLLM, FakeSandbox


def _finding(tmp: Path) -> PerfFinding:
    f = tmp / "mod.py"
    f.write_text(
        "def slow(xs, ys):\n"
        "    out = []\n"
        "    for x in xs:\n"
        "        if x in ys:\n"
        "            out.append(x)\n"
        "    return out\n"
        "\n"
        "def sample_inputs():\n"
        "    return {'slow': (list(range(100)), list(range(50, 150)))}\n",
        encoding="utf-8",
    )
    return PerfFinding(
        category=PerfCategory.LINEAR_SEARCH_IN_LOOP,
        severity=Severity.MEDIUM,
        title="`in` list lookup in loop",
        description="O(n²) linear search inside a loop",
        location=CodeLocation(file=f, start_line=1, end_line=6),
        function_name="slow",
        rule_id="efficiency.linear-search-in-loop",
    )


def test_savings_math():
    s = Savings(runtime_saved_ms_per_call=2.0, calls_per_year=3_600_000)
    # 2ms * 3.6M = 7.2M ms = 7200s = 2 hours saved.
    assert abs(s.hours_saved_per_year - 2.0) < 0.001
    # 2 hrs * $0.10 = $0.20
    assert abs(s.annual_dollars - 0.20) < 0.001
    # 2 hrs * 35W = 70 Wh = 0.07 kWh; 0.07 * 442 = ~30.94 g CO₂
    assert 25 < s.annual_co2_grams < 35


def test_refactor_agent_accepts_valid_response(tmp_path):
    llm = FakeLLM({
        "performance engineer": {
            "refactored_code":
                "def slow(xs, ys):\n"
                "    ys_set = set(ys)\n"
                "    return [x for x in xs if x in ys_set]\n",
            "explanation": "Convert list lookup to set lookup. O(n²) -> O(n).",
            "benchmark_script": "print('BENCH_RESULT:{\"runtime_ms_old\":10,\"runtime_ms_new\":1,\"iterations\":30,\"outputs_match\":true,\"inputs_description\":\"sample\"}')\n",
            "complexity_before": "O(n²)",
            "complexity_after": "O(n)",
            "references": [],
        }
    })
    f = _finding(tmp_path)
    out = RefactorAgent(llm).run_finding(f, AgentContext(repo_root=tmp_path))
    assert out.status == PerfStatus.REFACTORED
    assert out.refactoring is not None
    assert "set(" in out.refactoring.refactored_code
    assert "BENCH_RESULT" in out.refactoring.benchmark_script


def test_refactor_agent_rejects_broken_syntax(tmp_path):
    llm = FakeLLM({
        "performance engineer": {
            "refactored_code": "def slow(xs ys):  return ???",  # broken syntax
            "explanation": "x",
            "benchmark_script": "print('hi')\n",
        }
    })
    f = _finding(tmp_path)
    out = RefactorAgent(llm).run_finding(f, AgentContext(repo_root=tmp_path))
    assert out.status == PerfStatus.FAILED
    assert out.refactoring is None


def test_verifier_marks_verified_on_good_benchmark(tmp_path):
    f = _finding(tmp_path)
    f.refactoring = Refactoring(
        location=f.location,
        original_code="",
        refactored_code="def slow(xs, ys):\n    return list(set(xs) & set(ys))\n",
        explanation="x",
        benchmark_script="run the bench",  # not actually run; sandbox is faked
    )
    f.status = PerfStatus.REFACTORED

    sandbox = FakeSandbox(verdicts=[SandboxResult(
        exit_code=0,
        stdout='BENCH_RESULT:{"runtime_ms_old":10.0,"runtime_ms_new":1.0,"iterations":30,"outputs_match":true,"inputs_description":"two 100-element lists"}\n',
        stderr="",
    )])
    out = VerifierAgent(FakeLLM({}), sandbox).run_finding(f, AgentContext(repo_root=tmp_path))
    assert out.status == PerfStatus.VERIFIED
    assert out.benchmark and out.benchmark.outputs_match
    assert out.benchmark.speedup_x == 10.0
    assert out.savings and out.savings.annual_dollars > 0
    # Refactored file should have been cleaned up.
    assert not (tmp_path / "_refactored.py").exists()


def test_verifier_fails_when_outputs_diverge(tmp_path):
    f = _finding(tmp_path)
    f.refactoring = Refactoring(
        location=f.location, original_code="", refactored_code="def slow(xs,ys): return None\n",
        explanation="x", benchmark_script="...",
    )
    f.status = PerfStatus.REFACTORED
    sandbox = FakeSandbox(verdicts=[SandboxResult(
        exit_code=0,
        stdout='BENCH_RESULT:{"runtime_ms_old":10.0,"runtime_ms_new":1.0,"iterations":30,"outputs_match":false,"inputs_description":""}\n',
        stderr="",
    )])
    out = VerifierAgent(FakeLLM({}), sandbox).run_finding(f, AgentContext(repo_root=tmp_path))
    assert out.status == PerfStatus.FAILED
    assert any("DIFFERENT output" in n for n in out.notes)


def test_verifier_fails_when_no_speedup(tmp_path):
    f = _finding(tmp_path)
    f.refactoring = Refactoring(
        location=f.location, original_code="", refactored_code="def slow(xs,ys): return list(xs)\n",
        explanation="x", benchmark_script="...",
    )
    f.status = PerfStatus.REFACTORED
    sandbox = FakeSandbox(verdicts=[SandboxResult(
        exit_code=0,
        stdout='BENCH_RESULT:{"runtime_ms_old":10.0,"runtime_ms_new":12.0,"iterations":30,"outputs_match":true,"inputs_description":""}\n',
        stderr="",
    )])
    out = VerifierAgent(FakeLLM({}), sandbox).run_finding(f, AgentContext(repo_root=tmp_path))
    assert out.status == PerfStatus.FAILED
    assert any("did NOT improve" in n for n in out.notes)
