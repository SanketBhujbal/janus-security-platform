"""Tests for the efficiency roadmap features:
P1 (lang dispatch), P2 (savings config), P3 (memory), P4 (PR dedup),
P7 (profile import), P8 (history), P12 (multi-candidate)."""
from __future__ import annotations

from pathlib import Path

from orchestrator.agents.base import AgentContext
from orchestrator.agents.verifier import VerifierAgent
from orchestrator.exploits.runner import SandboxResult
from orchestrator.git_ops.efficiency_pr_body import (
    dedup_findings,
    fingerprints_in_body,
    render_efficiency_body,
)
from orchestrator.models.perf import (
    Candidate,
    GRID_INTENSITY_PRESETS,
    PerfCategory,
    PerfFinding,
    PerfStatus,
    Refactoring,
    Savings,
    SavingsConfig,
)
from orchestrator.models.vulnerability import CodeLocation, Severity
from orchestrator.perf_history import PerfHistory
from orchestrator.profile_import import parse_profile_json

from .fakes import FakeLLM, FakeSandbox


def _bench_line(old, new, match=True, mem_old=None, mem_new=None):
    import json
    payload = {"runtime_ms_old": old, "runtime_ms_new": new, "iterations": 30,
               "outputs_match": match, "inputs_description": "x"}
    if mem_old is not None:
        payload["memory_kb_old"] = mem_old
        payload["memory_kb_new"] = mem_new
    return "BENCH_RESULT:" + json.dumps(payload) + "\n"


def _finding(tmp: Path) -> PerfFinding:
    f = tmp / "mod.py"
    f.write_text(
        "def slow(xs, ys):\n    return [x for x in xs if x in ys]\n\n"
        "def sample_inputs():\n    return {'slow': ([1,2],[2,3])}\n",
        encoding="utf-8")
    return PerfFinding(
        category=PerfCategory.LINEAR_SEARCH_IN_LOOP,
        severity=Severity.MEDIUM,
        title="t", description="d",
        location=CodeLocation(file=f, start_line=1, end_line=2),
        function_name="slow", rule_id="efficiency.linear-search-in-loop",
        language="python",
    )


# ---------------- P2: savings config ----------------
def test_savings_config_grid_presets():
    cfg = SavingsConfig.from_request(grid_region="france")
    assert cfg.grid_intensity_g_co2_per_kwh == GRID_INTENSITY_PRESETS["france"]
    assert cfg.grid_region == "france"
    cfg2 = SavingsConfig.from_request(grid_intensity_g_co2_per_kwh=123.0)
    assert cfg2.grid_region == "custom" and cfg2.grid_intensity_g_co2_per_kwh == 123.0


def test_savings_from_config_threads_assumptions():
    cfg = SavingsConfig.from_request(calls_per_year=7_200_000, cpu_cost_per_hour_usd=0.272)
    s = Savings.from_config(cfg, runtime_saved_ms_per_call=2.0)
    # 2ms * 7.2M = 4 hours; 4h * $0.272 = $1.088
    assert abs(s.hours_saved_per_year - 4.0) < 1e-6
    assert abs(s.annual_dollars - 1.088) < 1e-3
    assert s.as_dict()["grid_region"] == cfg.grid_region


# ---------------- P3: memory ----------------
def test_memory_savings_surfaced():
    cfg = SavingsConfig()
    s = Savings.from_config(cfg, runtime_saved_ms_per_call=1.0, memory_saved_kb_per_call=2048.0)
    assert abs(s.memory_saved_mb_per_call - 2.0) < 1e-6
    assert s.as_dict()["memory_saved_mb_per_call"] == 2.0


def test_verifier_computes_memory_savings(tmp_path):
    f = _finding(tmp_path)
    f.refactoring = Refactoring(location=f.location, original_code="",
                                refactored_code="def slow(xs, ys):\n    return list(set(xs)&set(ys))\n",
                                benchmark_script="BENCH_RESULT placeholder")
    f.status = PerfStatus.REFACTORED
    sandbox = FakeSandbox(verdicts=[SandboxResult(0, _bench_line(10.0, 2.0, mem_old=5000, mem_new=1000), "")])
    out = VerifierAgent(FakeLLM({}), sandbox).run_finding(f, AgentContext(repo_root=tmp_path))
    assert out.status == PerfStatus.VERIFIED
    assert out.savings.memory_saved_kb_per_call == 4000.0


# ---------------- P12: multi-candidate ----------------
def test_verifier_picks_fastest_candidate(tmp_path):
    f = _finding(tmp_path)
    f.refactoring = Refactoring(location=f.location, original_code="",
                                refactored_code="def slow(xs, ys):\n    return list(xs)\n",
                                benchmark_script="shared bench")
    f.candidates = [
        Candidate(refactored_code="def slow(xs, ys):\n    return [x for x in xs if x in set(ys)]\n",
                  explanation="set-comp", confidence=0.9),
        Candidate(refactored_code="def slow(xs, ys):\n    return list(set(xs) & set(ys))\n",
                  explanation="set-intersection", confidence=0.7),
    ]
    f.status = PerfStatus.REFACTORED
    # candidate[0] -> 2x, candidate[1] -> 10x (faster). Verifier should pick #1.
    sandbox = FakeSandbox(verdicts=[
        SandboxResult(0, _bench_line(10.0, 5.0), ""),
        SandboxResult(0, _bench_line(10.0, 1.0), ""),
    ])
    out = VerifierAgent(FakeLLM({}), sandbox).run_finding(f, AgentContext(repo_root=tmp_path))
    assert out.status == PerfStatus.VERIFIED
    assert "set(xs) & set(ys)" in out.refactoring.refactored_code  # the faster one
    assert out.refactoring.runner_up_code  # the slower candidate kept as alternative
    assert out.benchmark.speedup_x == 10.0


# ---------------- P1: language dispatch ----------------
def test_verifier_java_toolchain_missing_keeps_refactored(tmp_path, monkeypatch):
    import orchestrator.agents.verifier as v
    monkeypatch.setattr(v.shutil, "which", lambda *_: None)
    f = _finding(tmp_path)
    f.language = "java"
    f.refactoring = Refactoring(location=f.location, original_code="",
                                refactored_code="int f(){return 0;}",
                                benchmark_script="class Bench{} // BENCH_RESULT")
    f.candidates = [Candidate(refactored_code="int f(){return 0;}",
                              benchmark_program="class Bench{} // BENCH_RESULT", confidence=1.0)]
    f.status = PerfStatus.REFACTORED
    out = VerifierAgent(FakeLLM({}), FakeSandbox()).run_finding(f, AgentContext(repo_root=tmp_path))
    assert out.status == PerfStatus.REFACTORED
    assert any("verification skipped" in n for n in out.notes)


# ---------------- P7: profile import ----------------
def test_profile_import_flat_and_native():
    flat = parse_profile_json('{"process_payment": 50000000, "mask_pan": 1200000}')
    assert flat["process_payment"]["calls_per_year"] == 50000000
    native = parse_profile_json('{"functions":[{"name":"a.b.findCommon","calls_per_year":42,"source":"datadog"}]}')
    assert native["findCommon"]["calls_per_year"] == 42
    assert native["findCommon"]["source"] == "datadog"


def test_profile_import_speedscope():
    doc = """
    {"shared": {"frames": [{"name": "main"}, {"name": "hot_fn"}]},
     "profiles": [{"samples": [[0,1],[0,1],[0,1],[0]], "weights": [1,1,1,1]}]}
    """
    hints = parse_profile_json(doc, total_calls_per_year=4_000_000)
    # hot_fn is the leaf of 3 of 4 samples -> 75% of 4M = 3M.
    assert hints["hot_fn"]["calls_per_year"] == 3_000_000


def test_brain_applies_profile_hint(tmp_path):
    f = _finding(tmp_path)
    f.refactoring = Refactoring(location=f.location, original_code="",
                                refactored_code="def slow(xs, ys):\n    return list(set(xs)&set(ys))\n",
                                benchmark_script="x")
    f.status = PerfStatus.REFACTORED
    f.calls_per_year_override = 100_000_000
    sandbox = FakeSandbox(verdicts=[SandboxResult(0, _bench_line(10.0, 1.0), "")])
    out = VerifierAgent(FakeLLM({}), sandbox,
                        savings_config=SavingsConfig(calls_per_year=3_600_000)
                        ).run_finding(f, AgentContext(repo_root=tmp_path))
    assert out.savings.calls_per_year == 100_000_000  # override beats global default


# ---------------- P8: history ----------------
def test_perf_history_dedup(tmp_path):
    f = _finding(tmp_path)
    f.status = PerfStatus.VERIFIED
    f.savings = Savings(runtime_saved_ms_per_call=2.0, calls_per_year=3_600_000)
    report = {"findings": [f.to_dict()]}
    hist = PerfHistory(tmp_path)
    assert hist.record_run(report) == 1     # newly added
    assert hist.record_run(report) == 0     # same fingerprint -> updated, not added
    totals = hist.totals()
    assert totals["verified_count"] == 1
    assert totals["runs"] == 2
    entry = hist.as_dict()["entries"][0]
    assert entry["times_verified"] == 2


# ---------------- P4: PR dedup ----------------
def test_pr_body_fingerprint_dedup(tmp_path):
    f = _finding(tmp_path)
    f.status = PerfStatus.VERIFIED
    f.savings = Savings(runtime_saved_ms_per_call=2.0)
    f.refactoring = Refactoring(location=f.location, original_code="orig",
                                refactored_code="new", benchmark_script="b")
    fd = f.to_dict()
    body = render_efficiency_body([fd], {"total_annual_dollars": 1.0, "total_annual_co2_grams": 1.0})
    fps = fingerprints_in_body(body)
    assert f.fingerprint in fps
    remaining, skipped = dedup_findings([fd], [body])
    assert remaining == [] and skipped == [f.fingerprint]
