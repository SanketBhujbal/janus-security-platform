"""Cumulative efficiency savings history (P8).

Each `perf_report.json` is overwritten per run, so on its own it can't tell the
story leadership actually wants: "this quarter we optimized N functions, saving
$X/yr and Y kg CO₂/yr." This module keeps an append-and-dedup ledger keyed by
finding fingerprint (file + function + category) so re-running a scan updates an
entry rather than double-counting it.

The ledger lives at `<repo>/.security_workdir/perf_history.json`.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("efficiency_brain.history")


class PerfHistory:
    def __init__(self, repo_root: Path):
        self.path = Path(repo_root) / ".security_workdir" / "perf_history.json"

    # ------------------------------------------------------------------
    def _load(self) -> dict:
        if not self.path.exists():
            return {"entries": {}, "runs": 0, "updated_at": ""}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            log.warning("perf_history: could not parse %s; starting fresh", self.path)
            return {"entries": {}, "runs": 0, "updated_at": ""}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    # ------------------------------------------------------------------
    def record_run(self, report: dict) -> int:
        """Fold a report's VERIFIED findings into the ledger. Returns the count
        of findings that were newly added (vs. updated)."""
        data = self._load()
        entries: dict = data.get("entries", {})
        now = datetime.now(timezone.utc).isoformat()
        added = 0

        for f in report.get("findings", []):
            if f.get("status") != "verified":
                continue
            fp = f.get("fingerprint") or ""
            if not fp:
                continue
            savings = f.get("savings") or {}
            bench = f.get("benchmark") or {}
            ref = f.get("refactoring") or {}
            loc = f.get("location") or {}
            payload = {
                "fingerprint":   fp,
                "file":          loc.get("file", ""),
                "function":      f.get("function_name", ""),
                "category":      f.get("category", ""),
                "language":      f.get("language", ""),
                "annual_dollars":   float(savings.get("annual_dollars") or 0.0),
                "annual_co2_grams": float(savings.get("annual_co2_grams") or 0.0),
                "memory_saved_mb_per_call": float(savings.get("memory_saved_mb_per_call") or 0.0),
                "speedup_x":     float(bench.get("speedup_x") or 0.0),
                "complexity_before": ref.get("complexity_before", ""),
                "complexity_after":  ref.get("complexity_after", ""),
                "last_verified": now,
            }
            if fp in entries:
                payload["first_seen"] = entries[fp].get("first_seen", now)
                payload["times_verified"] = int(entries[fp].get("times_verified", 1)) + 1
            else:
                payload["first_seen"] = now
                payload["times_verified"] = 1
                added += 1
            entries[fp] = payload

        data["entries"] = entries
        data["runs"] = int(data.get("runs", 0)) + 1
        data["updated_at"] = now
        self._save(data)
        return added

    # ------------------------------------------------------------------
    def totals(self) -> dict:
        data = self._load()
        entries = list(data.get("entries", {}).values())
        return {
            "verified_count":        len(entries),
            "total_annual_dollars":  round(sum(e.get("annual_dollars", 0.0) for e in entries), 2),
            "total_annual_co2_grams": round(sum(e.get("annual_co2_grams", 0.0) for e in entries), 2),
            "total_memory_mb_per_call": round(
                sum(e.get("memory_saved_mb_per_call", 0.0) for e in entries), 4),
            "runs":                  int(data.get("runs", 0)),
            "updated_at":            data.get("updated_at", ""),
        }

    def as_dict(self) -> dict:
        data = self._load()
        out = dict(self.totals())
        # Most valuable first.
        entries = sorted(
            data.get("entries", {}).values(),
            key=lambda e: e.get("annual_dollars", 0.0), reverse=True)
        out["entries"] = entries
        # Savings grouped by category — feeds the leadership bar chart.
        by_cat: dict[str, dict] = {}
        for e in entries:
            cat = e.get("category", "other")
            agg = by_cat.setdefault(cat, {"count": 0, "annual_dollars": 0.0, "annual_co2_grams": 0.0})
            agg["count"] += 1
            agg["annual_dollars"] += e.get("annual_dollars", 0.0)
            agg["annual_co2_grams"] += e.get("annual_co2_grams", 0.0)
        out["by_category"] = by_cat
        return out
