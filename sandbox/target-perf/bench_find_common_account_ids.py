"""Benchmark: find_common_account_ids  old vs new."""
import sys
import time
import json

REPO_PATH = r"C:\Users\bhujbalsa\security_orchestrator\sandbox\target-perf"
sys.path.insert(0, REPO_PATH)

try:
    import inefficient as old
except ImportError as e:
    print(f"BENCH_FAIL:Could not import inefficient: {e}")
    sys.exit(0)

try:
    import _refactored as new
except ImportError as e:
    print(f"BENCH_FAIL:Could not import _refactored: {e}")
    sys.exit(0)

FUNC = "find_common_account_ids"

try:
    inputs = old.sample_inputs()
    args = inputs[FUNC]
except Exception as e:
    print(f"BENCH_FAIL:sample_inputs() error: {e}")
    sys.exit(0)

# ---------- correctness check ----------
try:
    out_old = old.find_common_account_ids(*args)
    out_new = new.find_common_account_ids(*args)
    outputs_match = sorted(out_old) == sorted(out_new)
    if not outputs_match:
        print(
            f"BENCH_FAIL:Output mismatch old={out_old[:5]} new={out_new[:5]}"
        )
        sys.exit(0)
except Exception as e:
    print(f"BENCH_FAIL:Execution error during correctness check: {e}")
    sys.exit(0)

# ---------- timing ----------
iterations = 30

t0 = time.perf_counter_ns()
for _ in range(iterations):
    old.find_common_account_ids(*args)
t1 = time.perf_counter_ns()
runtime_ms_old = (t1 - t0) / 1_000_000

t2 = time.perf_counter_ns()
for _ in range(iterations):
    new.find_common_account_ids(*args)
t3 = time.perf_counter_ns()
runtime_ms_new = (t3 - t2) / 1_000_000

result = {
    "runtime_ms_old": round(runtime_ms_old, 3),
    "runtime_ms_new": round(runtime_ms_new, 3),
    "iterations": iterations,
    "outputs_match": outputs_match,
    "inputs_description": "account_ids_a=list(range(0,4000)), account_ids_b=list(range(2000,6000)) -> 2000 common ids",
}

print(f"BENCH_RESULT:{json.dumps(result)}")
