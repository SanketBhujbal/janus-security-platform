"""Data model for the efficiency mission.

This is the "Code Sentinel — efficiency mode" twin of `vulnerability.py`.
Same 4-stage pipeline (profile -> simulate/benchmark -> refactor -> verify),
different signal (algorithmic / resource inefficiency, not security risk).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from .vulnerability import CodeLocation, Severity


class PerfCategory(str, Enum):
    NESTED_LOOP_SAME_ITERABLE = "nested_loop_same_iterable"
    LINEAR_SEARCH_IN_LOOP     = "linear_search_in_loop"
    STRING_CONCAT_IN_LOOP     = "string_concat_in_loop"
    REGEX_RECOMPILE_IN_LOOP   = "regex_recompile_in_loop"
    REPEATED_SORT_IN_LOOP     = "repeated_sort_in_loop"
    APPEND_BUILD_LIST         = "append_build_list"  # candidate for comprehension
    LINQ_INEFFICIENT          = "linq_inefficient"   # .NET LINQ anti-patterns
    BOXING_IN_LOOP            = "boxing_in_loop"     # Java autoboxing in hot path
    OTHER                     = "other"


class PerfStatus(str, Enum):
    DISCOVERED  = "discovered"     # profiler flagged it
    BENCHMARKED = "benchmarked"    # we have baseline numbers
    REFACTORED  = "refactored"     # LLM proposed + applied a refactor
    VERIFIED    = "verified"       # outputs match AND new code is faster
    FAILED      = "failed"         # something broke (outputs diverged, refactor unparseable, etc.)


@dataclass
class BenchmarkResult:
    runtime_ms_old: float = 0.0
    runtime_ms_new: float = 0.0
    iterations: int = 0
    memory_kb_old: Optional[float] = None
    memory_kb_new: Optional[float] = None
    outputs_match: bool = False
    inputs_description: str = ""
    raw_stdout: str = ""

    @property
    def speedup_x(self) -> float:
        if not self.runtime_ms_new or self.runtime_ms_new == 0:
            return 0.0
        return self.runtime_ms_old / self.runtime_ms_new

    @property
    def runtime_saved_ms_per_call(self) -> float:
        return max(0.0, self.runtime_ms_old - self.runtime_ms_new)

    @property
    def memory_saved_kb_per_call(self) -> float:
        if self.memory_kb_old is None or self.memory_kb_new is None:
            return 0.0
        return max(0.0, float(self.memory_kb_old) - float(self.memory_kb_new))

    @property
    def memory_reduction_pct(self) -> float:
        if not self.memory_kb_old:
            return 0.0
        return 100.0 * self.memory_saved_kb_per_call / float(self.memory_kb_old)


@dataclass
class Refactoring:
    location: CodeLocation
    original_code: str
    refactored_code: str
    explanation: str = ""
    references: list[str] = field(default_factory=list)
    benchmark_script: str = ""    # Python that imports both, runs both, prints JSON
    complexity_before: str = ""
    complexity_after: str = ""
    # Multi-candidate (P12): the runner-up the verifier benchmarked but did not
    # pick, kept so the PR can surface a second option (à la Snyk Agent Fix's
    # multi-candidate suggestions, but each one benchmark-checked).
    runner_up_code: str = ""
    runner_up_note: str = ""


# Map file extension -> the language tag the verifier dispatches on.
LANG_BY_EXT: dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".cs": "dotnet",
}


@dataclass
class Candidate:
    """One LLM-proposed refactor variant before verification. The verifier
    benchmarks each candidate and the brain keeps the fastest correct one."""
    refactored_code: str
    explanation: str = ""
    complexity_before: str = ""
    complexity_after: str = ""
    references: list[str] = field(default_factory=list)
    confidence: float = 0.0       # LLM self-reported 0..1
    benchmark_program: str = ""   # self-contained driver for compiled langs (Java/.NET)
    benchmark: Optional["BenchmarkResult"] = None
    rejected_reason: str = ""


# Grid carbon intensity presets (gCO₂/kWh). The UI exposes these as a dropdown
# so a team can pick the region their workload actually runs in -- a French
# (mostly-nuclear) datacenter is ~8× cleaner than the global average, which
# materially changes the CO₂ story. Sources: IEA 2023 / Ember 2023 averages.
GRID_INTENSITY_PRESETS: dict[str, float] = {
    "global":     442.0,   # IEA global average 2023
    "us":         369.0,   # US grid average
    "eu":         251.0,   # EU-27 average
    "france":      56.0,   # mostly nuclear
    "nordics":     45.0,   # hydro/nuclear heavy
    "india":      632.0,   # coal heavy
    "aws_us_east": 379.0,  # cloud-region proxy
}


@dataclass
class SavingsConfig:
    """The tunable economic / environmental assumptions behind a Savings
    projection. Threaded from the webapp form -> EfficiencyBrain -> VerifierAgent
    so a user can model their own instance price, call volume, and grid region
    without editing code."""
    calls_per_year: int = 3_600_000
    cpu_cost_per_hour_usd: float = 0.10
    grid_intensity_g_co2_per_kwh: float = 442.0
    avg_cpu_power_watts: float = 35.0
    grid_region: str = "global"

    @classmethod
    def from_request(
        cls,
        calls_per_year: int | None = None,
        cpu_cost_per_hour_usd: float | None = None,
        grid_region: str | None = None,
        grid_intensity_g_co2_per_kwh: float | None = None,
        avg_cpu_power_watts: float | None = None,
    ) -> "SavingsConfig":
        cfg = cls()
        if calls_per_year is not None:
            cfg.calls_per_year = int(calls_per_year)
        if cpu_cost_per_hour_usd is not None:
            cfg.cpu_cost_per_hour_usd = float(cpu_cost_per_hour_usd)
        if avg_cpu_power_watts is not None:
            cfg.avg_cpu_power_watts = float(avg_cpu_power_watts)
        # Region preset wins unless an explicit intensity is supplied.
        if grid_region:
            cfg.grid_region = grid_region
            cfg.grid_intensity_g_co2_per_kwh = GRID_INTENSITY_PRESETS.get(
                grid_region, cfg.grid_intensity_g_co2_per_kwh
            )
        if grid_intensity_g_co2_per_kwh is not None:
            cfg.grid_intensity_g_co2_per_kwh = float(grid_intensity_g_co2_per_kwh)
            cfg.grid_region = "custom"
        return cfg

    def note(self) -> str:
        return (
            f"Assumes {self.calls_per_year:,} calls/yr, "
            f"${self.cpu_cost_per_hour_usd:.3f}/CPU-hour, "
            f"~{self.avg_cpu_power_watts:.0f}W avg CPU draw, and "
            f"{self.grid_intensity_g_co2_per_kwh:.0f} gCO₂/kWh "
            f"(grid: {self.grid_region}). Tune in the UI."
        )


@dataclass
class Savings:
    """Estimated yearly impact assuming the refactored hot path is called
    `calls_per_year` times. Defaults are conservative for a typical
    payments microservice path (≈3.6M calls/yr = 10k/day = ~7 RPM)."""
    runtime_saved_ms_per_call: float = 0.0
    calls_per_year: int = 3_600_000
    cpu_cost_per_hour_usd: float = 0.10           # generic small instance
    grid_intensity_g_co2_per_kwh: float = 442.0   # global avg per IEA 2023
    avg_cpu_power_watts: float = 35.0             # conservative server CPU pull
    memory_saved_kb_per_call: float = 0.0         # peak-alloc delta from tracemalloc
    grid_region: str = "global"
    assumption_note: str = (
        "Assumes ~10k calls/day, $0.10/CPU-hour, ~35W avg CPU draw, "
        "and 442 gCO₂/kWh (IEA global avg). Tune in code or the UI."
    )

    @classmethod
    def from_config(
        cls,
        cfg: SavingsConfig,
        runtime_saved_ms_per_call: float = 0.0,
        memory_saved_kb_per_call: float = 0.0,
    ) -> "Savings":
        return cls(
            runtime_saved_ms_per_call=runtime_saved_ms_per_call,
            calls_per_year=cfg.calls_per_year,
            cpu_cost_per_hour_usd=cfg.cpu_cost_per_hour_usd,
            grid_intensity_g_co2_per_kwh=cfg.grid_intensity_g_co2_per_kwh,
            avg_cpu_power_watts=cfg.avg_cpu_power_watts,
            memory_saved_kb_per_call=memory_saved_kb_per_call,
            grid_region=cfg.grid_region,
            assumption_note=cfg.note(),
        )

    @property
    def hours_saved_per_year(self) -> float:
        return (self.runtime_saved_ms_per_call * self.calls_per_year) / 1000.0 / 3600.0

    @property
    def annual_dollars(self) -> float:
        return self.hours_saved_per_year * self.cpu_cost_per_hour_usd

    @property
    def annual_co2_grams(self) -> float:
        # power_kwh = hours * watts / 1000
        # co2_g     = power_kwh * grid_intensity
        kwh = self.hours_saved_per_year * self.avg_cpu_power_watts / 1000.0
        return kwh * self.grid_intensity_g_co2_per_kwh

    @property
    def memory_saved_mb_per_call(self) -> float:
        return self.memory_saved_kb_per_call / 1024.0

    @property
    def annual_memory_gb_hours(self) -> float:
        # A rough "memory pressure relieved" metric: MB freed per call × calls/yr,
        # expressed as GB to keep the number legible. Useful signal for GC-heavy
        # JVM/.NET services where allocation churn drives pause time.
        return (self.memory_saved_mb_per_call * self.calls_per_year) / 1024.0

    def as_dict(self) -> dict:
        return {
            "runtime_saved_ms_per_call": round(self.runtime_saved_ms_per_call, 4),
            "memory_saved_kb_per_call":  round(self.memory_saved_kb_per_call, 2),
            "memory_saved_mb_per_call":  round(self.memory_saved_mb_per_call, 4),
            "annual_memory_gb_hours":    round(self.annual_memory_gb_hours, 2),
            "calls_per_year":            self.calls_per_year,
            "cpu_cost_per_hour_usd":     self.cpu_cost_per_hour_usd,
            "grid_region":               self.grid_region,
            "grid_intensity_g_co2_per_kwh": self.grid_intensity_g_co2_per_kwh,
            "hours_saved_per_year":      round(self.hours_saved_per_year, 4),
            "annual_dollars":            round(self.annual_dollars, 2),
            "annual_co2_grams":          round(self.annual_co2_grams, 2),
            "assumption_note":           self.assumption_note,
        }


@dataclass
class PerfFinding:
    category: PerfCategory
    severity: Severity
    title: str
    description: str
    location: CodeLocation
    function_name: str = ""
    rule_id: Optional[str] = None
    language: str = "python"          # python | java | dotnet (drives benchmark dispatch)
    benchmark: Optional[BenchmarkResult] = None
    refactoring: Optional[Refactoring] = None
    savings: Optional[Savings] = None
    status: PerfStatus = PerfStatus.DISCOVERED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    notes: list[str] = field(default_factory=list)
    # Multi-candidate refactoring trail (P12). Populated by RefactorAgent +
    # VerifierAgent; surfaced in the report so reviewers see what was tried.
    candidates: list[Candidate] = field(default_factory=list)
    # Per-finding call-rate override (P7). When a runtime profile says this
    # exact function is called N times/sec, that beats the global default and
    # makes the savings projection real instead of assumed.
    calls_per_year_override: Optional[int] = None
    runtime_hint_note: str = ""       # human-readable source of the override

    @property
    def fingerprint(self) -> str:
        """Stable identity for a finding across runs: file + function + category.
        Used for PR dedup (P4) and cumulative-history keying (P8). Path is made
        relative-ish by taking just the file name + function so the same logical
        finding matches even if the repo is checked out at a different abs path."""
        import hashlib
        basis = f"{self.location.file.name}::{self.function_name}::{self.category.value}"
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        def _serialize(obj: Any) -> Any:
            # Savings has computed @properties (annual_dollars, annual_co2_grams)
            # that the generic __dict__ walk would miss. Route through its
            # explicit as_dict() so the report carries the numbers, not just
            # the raw inputs.
            if isinstance(obj, Savings):
                return obj.as_dict()
            if isinstance(obj, Path):
                return str(obj)
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, list):
                return [_serialize(x) for x in obj]
            if isinstance(obj, dict):
                return {k: _serialize(v) for k, v in obj.items()}
            if hasattr(obj, "__dict__"):
                return {k: _serialize(v) for k, v in obj.__dict__.items()}
            return obj
        d = _serialize(self)
        # fingerprint is a computed @property -> not in __dict__; inject it so
        # the report / PR-dedup / history layers can key on it.
        d["fingerprint"] = self.fingerprint
        if self.benchmark is not None:
            d["benchmark"]["speedup_x"] = round(self.benchmark.speedup_x, 3)
            d["benchmark"]["memory_saved_kb_per_call"] = round(
                self.benchmark.memory_saved_kb_per_call, 2)
        return d
