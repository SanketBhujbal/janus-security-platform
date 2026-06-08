"""Runtime profile import (P7).

Static analysis flags a pattern regardless of whether the enclosing function runs
once a night or ten million times a second. Feeding a real runtime profile in
lets the savings projection reflect actual production hotness instead of a flat
default — and lets prioritization favour genuinely hot code.

Accepts three shapes, all keyed/normalized to {function_name: {calls_per_year, source}}:

1. Native hints:    {"functions": [{"name": "f", "calls_per_year": 50000000, "source": "datadog"}]}
2. Flat mapping:    {"process_payment": 50000000, "mask_pan": 1200000}
3. speedscope JSON  (py-spy --format speedscope, Pyroscope export): frame sample
   counts are converted to a share of a total annual call budget.
"""
from __future__ import annotations

import json
import logging
from typing import Any

log = logging.getLogger("efficiency_brain.profile")

DEFAULT_TOTAL_CALLS_PER_YEAR = 3_600_000


def parse_profile_json(text: str, total_calls_per_year: int = DEFAULT_TOTAL_CALLS_PER_YEAR) -> dict[str, dict]:
    """Parse a profile document into per-function call-rate hints."""
    if not text or not text.strip():
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        log.warning("profile import: invalid JSON: %s", e)
        return {}

    if isinstance(data, dict) and "functions" in data and isinstance(data["functions"], list):
        return _parse_native(data["functions"])
    if isinstance(data, dict) and _looks_like_speedscope(data):
        return _parse_speedscope(data, total_calls_per_year)
    if isinstance(data, dict):
        return _parse_flat(data)
    log.warning("profile import: unrecognized profile shape")
    return {}


def _parse_native(funcs: list) -> dict[str, dict]:
    hints: dict[str, dict] = {}
    for item in funcs:
        if not isinstance(item, dict):
            continue
        name = _short_name(item.get("name") or item.get("function") or "")
        if not name:
            continue
        try:
            calls = int(item.get("calls_per_year") or item.get("calls") or 0)
        except (TypeError, ValueError):
            continue
        if calls > 0:
            hints[name] = {"calls_per_year": calls, "source": item.get("source", "profile")}
    return hints


def _parse_flat(data: dict) -> dict[str, dict]:
    hints: dict[str, dict] = {}
    for name, val in data.items():
        try:
            calls = int(val)
        except (TypeError, ValueError):
            continue
        short = _short_name(name)
        if short and calls > 0:
            hints[short] = {"calls_per_year": calls, "source": "profile"}
    return hints


def _looks_like_speedscope(data: dict) -> bool:
    return "shared" in data and "profiles" in data and isinstance(data.get("profiles"), list)


def _parse_speedscope(data: dict, total_calls_per_year: int) -> dict[str, dict]:
    frames = (data.get("shared", {}) or {}).get("frames", []) or []
    frame_names = [_short_name(f.get("name", "")) for f in frames]
    counts: dict[int, int] = {}
    total_samples = 0
    for prof in data.get("profiles", []):
        samples = prof.get("samples", []) or []
        weights = prof.get("weights", None)
        for i, stack in enumerate(samples):
            w = 1
            if isinstance(weights, list) and i < len(weights):
                try:
                    w = int(weights[i])
                except (TypeError, ValueError):
                    w = 1
            # Attribute a sample to its leaf frame (top of stack).
            if stack:
                leaf = stack[-1]
                counts[leaf] = counts.get(leaf, 0) + w
                total_samples += w
    if total_samples == 0:
        return {}
    hints: dict[str, dict] = {}
    for frame_idx, c in counts.items():
        if 0 <= frame_idx < len(frame_names):
            name = frame_names[frame_idx]
            if not name:
                continue
            share = c / total_samples
            calls = int(round(share * total_calls_per_year))
            if calls > 0:
                # If two frames map to the same short name, keep the hotter one.
                prev = hints.get(name, {}).get("calls_per_year", 0)
                if calls > prev:
                    hints[name] = {
                        "calls_per_year": calls,
                        "source": f"speedscope ({share:.0%} of samples)",
                    }
    return hints


def _short_name(name: str) -> str:
    """Reduce a fully-qualified frame name to the bare function/method name so it
    matches PerfFinding.function_name. Handles `module.Class.method`, `pkg::fn`,
    and `path/file.py:func`."""
    if not name:
        return ""
    n = name.strip()
    for sep in ("(",):  # drop arg lists
        if sep in n:
            n = n.split(sep, 1)[0]
    n = n.replace("::", ".").replace("/", ".")
    if ":" in n:  # path:func
        n = n.split(":")[-1]
    if "." in n:
        n = n.split(".")[-1]
    return n.strip()
