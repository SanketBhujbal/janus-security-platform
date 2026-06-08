"""Intentionally inefficient code -- the efficiency loop's target.

Each function below has a deliberate algorithmic / resource problem that
maps 1:1 to a rule in orchestrator/rules/efficiency/. The functions are
real (callable with realistic inputs) so the benchmark / verify pipeline
can measure actual runtime + memory and compute $$$ / CO₂ savings.

These functions are also self-contained (no DB, no network) so the
sandbox can import + benchmark them safely.
"""
from __future__ import annotations

import re
from typing import Iterable


# -----------------------------------------------------------------
# Pattern 1: O(n²) -- linear `in` lookup against a list inside a loop.
# Should be: build a set once, then check membership in O(1).
# -----------------------------------------------------------------
def find_common_account_ids(account_ids_a, account_ids_b):
    common = []
    for aid in account_ids_a:
        if aid in account_ids_b:        # O(n) per lookup -> O(n*m)
            common.append(aid)
    return common


# -----------------------------------------------------------------
# Pattern 2: nested loop over the same collection.
# Should be: zip-pair iteration or hash-based grouping.
# -----------------------------------------------------------------
def find_duplicate_transaction_pairs(transactions):
    pairs = []
    for tx_a in transactions:
        for tx_b in transactions:                       # O(n²)
            if tx_a is tx_b:
                continue
            if tx_a["amount"] == tx_b["amount"] and tx_a["user_id"] == tx_b["user_id"]:
                pairs.append((tx_a["id"], tx_b["id"]))
    return pairs


# -----------------------------------------------------------------
# Pattern 3: string concatenation in a loop.
# Should be: list-append + ''.join at the end.
# -----------------------------------------------------------------
def build_csv_export(rows):
    out = ""
    for row in rows:
        out += ",".join(str(c) for c in row) + "\n"     # O(n²) memory churn
    return out


# -----------------------------------------------------------------
# Pattern 4: re.compile inside a loop.
# Should be: compile once outside the loop.
# -----------------------------------------------------------------
def mask_pan_in_log_lines(lines):
    masked = []
    for line in lines:
        pattern = re.compile(r"\b(\d{6})\d{6}(\d{4})\b")        # re-compiled each call
        masked.append(pattern.sub(r"\1******\2", line))
    return masked


# -----------------------------------------------------------------
# Synthetic test inputs the verifier / benchmark can use.
# Sized so each function takes a few ms cold, several hundred ms warm.
# -----------------------------------------------------------------
def sample_inputs() -> dict:
    a_ids = list(range(0, 4000))
    b_ids = list(range(2000, 6000))

    transactions = []
    for i in range(2000):
        transactions.append({
            "id": f"tx-{i:05d}",
            "user_id": i % 250,
            "amount": (i % 17) * 1.50,
        })

    rows = [[f"row{i}", i * 3, "alice@example.com", "USD", i % 99] for i in range(8000)]

    lines = [
        f"2026-05-21 charge: pan=4111222233334444 cvv=123 amount=12.{i:02d}"
        for i in range(3000)
    ]

    return {
        "find_common_account_ids":         (a_ids, b_ids),
        "find_duplicate_transaction_pairs": (transactions,),
        "build_csv_export":                (rows,),
        "mask_pan_in_log_lines":           (lines,),
    }


if __name__ == "__main__":
    # Quick local sanity check (not used by the orchestrator).
    inputs = sample_inputs()
    for name, args in inputs.items():
        func = globals()[name]
        out = func(*args)
        print(f"{name}: ok ({type(out).__name__}, len={len(out) if hasattr(out,'__len__') else '-'})")
