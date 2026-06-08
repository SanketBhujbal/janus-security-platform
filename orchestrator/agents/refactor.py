"""RefactorAgent — proposes more efficient version(s) of a flagged function AND
generates a benchmark driver. Sibling of HealerAgent (security mode).

This agent is:
  * multi-candidate (P12): it asks the LLM for several independent refactor
    variants, each with a self-reported confidence. The VerifierAgent then
    benchmarks every candidate and keeps the fastest one that is still correct.
  * language-aware (P1): Python, Java and C#/.NET each get a tailored prompt and
    benchmark protocol so the verify loop runs for all three, not just Python.
  * memory-aware (P3): the Python benchmark template uses `tracemalloc` so we
    can report peak-allocation savings alongside CPU time.

The LLM produces a single JSON object. For Python the driver is a shared
sibling-import script (`_refactored.py` is staged next to the original); for
Java/.NET each candidate ships a self-contained benchmark program (compiled and
run as one unit) since cross-file compilation is awkward in the sandbox.
"""
from __future__ import annotations

import ast
import logging
import textwrap

from ..models.perf import Candidate, PerfFinding, PerfStatus, Refactoring
from .base import Agent, AgentContext


log = logging.getLogger("security_brain.refactor")

# How many independent refactor variants to request from the LLM. Python gets
# the full multi-candidate treatment; compiled languages get a single best-shot
# because their benchmark programs are self-contained (no cheap candidate swap).
CANDIDATES_PER_LANG = {"python": 3, "java": 1, "dotnet": 1}

LANG_LABEL = {"python": "Python", "java": "Java", "dotnet": "C#/.NET"}


# --------------------------------------------------------------------------
# Prompt construction
# --------------------------------------------------------------------------
_PYTHON_BENCH_RULES = """\
Constraints for `benchmark_script` (Python, shared by all candidates):
- Pure Python, runnable with `python script.py`.
- It MUST import the ORIGINAL module via:
      import sys; sys.path.insert(0, <REPO_PATH>); import <MODULE> as old
- It MUST import the NEW function from a sibling file `_refactored.py` that the
  verifier stages alongside the original, swapping in each candidate in turn:
      import _refactored as new
- It MUST call `<MODULE>.sample_inputs()` to get test inputs (the seeded target
  ships one); use the entry keyed by the function name.
- Run the OLD function first and capture output; run NEW on the same inputs;
  assert outputs are equivalent (sort unordered results before comparing).
- Time with time.perf_counter_ns(); run each function ~30 iterations (cap ~2s).
- Measure PEAK MEMORY with tracemalloc around one representative call of each:
      import tracemalloc
      tracemalloc.start(); old(*args); _, peak_old = tracemalloc.get_traced_memory()
      tracemalloc.reset_peak(); new(*args); _, peak_new = tracemalloc.get_traced_memory()
      tracemalloc.stop()
  Report peaks in KILOBYTES (bytes / 1024).
- Print EXACTLY ONE line of JSON, prefixed `BENCH_RESULT:` then a newline:
    BENCH_RESULT:{"runtime_ms_old": <float>, "runtime_ms_new": <float>, \
"memory_kb_old": <float>, "memory_kb_new": <float>, "iterations": <int>, \
"outputs_match": <bool>, "inputs_description": "<str>"}
- On ANY error print `BENCH_FAIL:<one-line reason>` and exit 0.
- Under 20s total. No sleeps, no network, no writes outside the working dir."""

_COMPILED_BENCH_RULES = """\
Constraints for `benchmark_program` (one self-contained {label} program PER candidate):
- A SINGLE compilable file. It embeds BOTH the original implementation (named
  with an `Old` suffix) AND this candidate's optimized implementation (`New`
  suffix), generates realistic synthetic inputs inline (no external files, no
  DB, no network), runs both, and asserts the outputs are equal.
- Time with a monotonic clock ({timer}); run each ~20 iterations.
- Print EXACTLY ONE line to stdout, prefixed `BENCH_RESULT:` then newline:
    BENCH_RESULT:{{"runtime_ms_old": <float>, "runtime_ms_new": <float>, \
"iterations": <int>, "outputs_match": <bool>, "inputs_description": "<str>"}}
- On ANY error print `BENCH_FAIL:<reason>` and exit 0.
- {entry}
- Under 20s total. No network. stdlib/runtime only."""

_COMPILED_DETAILS = {
    "java": {
        "label": "Java",
        "timer": "System.nanoTime()",
        "entry": "Top-level public class MUST be named `Bench` with a "
                 "`public static void main(String[] args)` entry point.",
    },
    "dotnet": {
        "label": "C#",
        "timer": "System.Diagnostics.Stopwatch",
        "entry": "Use a top-level `Program` with a `Main`/top-level statements "
                 "that runs the benchmark and prints the BENCH_RESULT line.",
    },
}


def _system_prompt(language: str, num_candidates: int) -> str:
    label = LANG_LABEL.get(language, language)
    if num_candidates > 1:
        candidate_clause = (
            f"Produce {num_candidates} INDEPENDENT candidate refactors, ordered "
            "best-first, each with a self-reported `confidence` in [0,1]. Make "
            "them genuinely different strategies where possible (e.g. set-based "
            "vs. dict-grouping vs. comprehension) so the verifier can pick the "
            "fastest correct one."
        )
        candidates_schema = """\
  "candidates": [
    {
      "refactored_code": "<full replacement function source -- def/method + body>",
      "explanation":     "<2-4 sentences: what changed and why it's faster>",
      "complexity_before": "<e.g. O(n²)>",
      "complexity_after":  "<e.g. O(n)>",
      "confidence":        <float 0..1>,
      "references":        ["..."]
    }
  ],
  "benchmark_script": "<shared python driver as a single string>\""""
    else:
        candidate_clause = (
            "Produce ONE best-effort candidate refactor with a `confidence` in [0,1]."
        )
        candidates_schema = """\
  "candidates": [
    {
      "refactored_code": "<full replacement method source>",
      "explanation":     "<2-4 sentences>",
      "complexity_before": "<e.g. O(n²)>",
      "complexity_after":  "<e.g. O(n)>",
      "confidence":        <float 0..1>,
      "benchmark_program": "<full self-contained program as a single string>",
      "references":        ["..."]
    }
  ]"""

    if language == "python":
        bench_rules = _PYTHON_BENCH_RULES
        code_constraints = """\
Constraints for each `refactored_code`:
- Same function name, parameter signature, and return type as the original.
- Identical observable behavior on all reasonable inputs.
- No new third-party dependencies. Use stdlib only.
- Keep imports the function already relied on. Replace ONLY the function body
  (plus any small helpers you add inside it).
- Idiomatic Python. Prefer set / dict / comprehensions / generators for wins."""
    else:
        d = _COMPILED_DETAILS[language]
        bench_rules = _COMPILED_BENCH_RULES.format(**d)
        code_constraints = f"""\
Constraints for each `refactored_code`:
- Same method name, parameter types, and return type as the original.
- Identical observable behavior. No new third-party dependencies; {label} \
standard library / runtime only.
- Replace ONLY the method body. Keep it idiomatic {label}."""

    return textwrap.dedent(f"""\
        You are a senior performance engineer. Given an inefficient {label} \
        function and the surrounding file, produce faster, behavior-equivalent \
        replacement(s) AND a benchmark that proves old vs new produce identical \
        outputs while measuring the runtime delta.

        {candidate_clause}

        {code_constraints}

        {bench_rules}

        Respond with STRICT JSON only (no prose, no fences):
        {{
        {candidates_schema}
        }}
        """)


class RefactorAgent(Agent):
    name = "refactor"

    def run_finding(self, finding: PerfFinding, ctx: AgentContext) -> PerfFinding:
        language = (finding.language or "python").lower()
        if language not in LANG_LABEL:
            language = "python"

        try:
            file_text = finding.location.file.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            finding.status = PerfStatus.FAILED
            finding.notes.append(f"refactor: cannot read {finding.location.file}: {e}")
            return finding

        module_name = finding.location.file.stem
        original_func = self._slice_function(file_text, finding.function_name, language) \
            or finding.location.snippet

        num = CANDIDATES_PER_LANG.get(language, 1)
        system = _system_prompt(language, num)
        user_prompt = self._user_prompt(finding, module_name, original_func, file_text, language)

        try:
            spec = self.llm.complete_json(system, user_prompt)
        except Exception as e:
            finding.status = PerfStatus.FAILED
            finding.notes.append(f"refactor: LLM call failed: {type(e).__name__}: {e}")
            return finding

        candidates, shared_bench = self._extract_candidates(spec)
        if not candidates:
            finding.status = PerfStatus.FAILED
            finding.notes.append("refactor: LLM response had no usable candidates")
            return finding

        # Validate candidate code + (where shared) the benchmark script.
        valid: list[Candidate] = []
        for c in candidates:
            if not self._code_valid(c.refactored_code, language):
                log.warning("refactor: candidate failed %s validity check; dropping", language)
                continue
            bench = shared_bench or self._candidate_bench(spec, c)
            if not self._bench_valid(bench, language):
                log.warning("refactor: candidate benchmark failed validity check; dropping")
                continue
            valid.append(c)

        if not valid:
            finding.status = PerfStatus.FAILED
            finding.notes.append("refactor: all candidates failed syntax/structure checks; aborting")
            return finding

        valid.sort(key=lambda c: c.confidence, reverse=True)
        finding.candidates = valid
        primary = valid[0]
        finding.refactoring = Refactoring(
            location=finding.location,
            original_code=original_func,
            refactored_code=primary.refactored_code,
            explanation=primary.explanation,
            references=list(primary.references),
            benchmark_script=shared_bench or self._candidate_bench(spec, primary),
            complexity_before=primary.complexity_before,
            complexity_after=primary.complexity_after,
        )
        finding.status = PerfStatus.REFACTORED
        finding.notes.append(
            f"refactor: {len(valid)} candidate(s) generated "
            f"(top confidence {primary.confidence:.2f})"
        )
        return finding

    # ------------------------------------------------------------------
    def _user_prompt(self, finding, module_name, original_func, file_text, language) -> str:
        if language == "python":
            extra = (
                f"Module name (for `import {module_name} as old`): {module_name}\n"
                f"Repo path (for `sys.path.insert`): {finding.location.file.parent}\n"
                "Note: the file ships a `sample_inputs()` returning a dict keyed by "
                "function name -> tuple of args. Use it."
            )
        else:
            extra = (
                "There is no sample_inputs() helper for this language — your "
                "benchmark program must generate its own realistic synthetic "
                "inputs inline (a few thousand elements)."
            )
        return textwrap.dedent(
            f"""
            Inefficient function: `{finding.function_name}`  (category: {finding.category.value})
            Language: {LANG_LABEL.get(language, language)}
            Rule: {finding.rule_id}
            Location: {finding.location.as_pointer()}
            {extra}

            Original function source:
            ---
            {original_func}
            ---

            Surrounding file (imports + context):
            ---
            {file_text[:6000]}
            ---
            """
        ).strip()

    @staticmethod
    def _extract_candidates(spec: dict) -> tuple[list[Candidate], str]:
        """Return (candidates, shared_benchmark_script). Accepts the new
        multi-candidate schema and the legacy single-object schema."""
        shared_bench = (spec.get("benchmark_script") or "").strip()
        raw = spec.get("candidates")
        if not raw:
            # Legacy single-candidate schema.
            rc = (spec.get("refactored_code") or "").strip()
            if not rc:
                return [], shared_bench
            raw = [{
                "refactored_code": rc,
                "explanation": spec.get("explanation", ""),
                "complexity_before": spec.get("complexity_before", ""),
                "complexity_after": spec.get("complexity_after", ""),
                "confidence": 1.0,
                "references": spec.get("references", []),
                "benchmark_program": spec.get("benchmark_program", ""),
            }]
        out: list[Candidate] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            code = (item.get("refactored_code") or "").strip()
            if not code:
                continue
            try:
                conf = float(item.get("confidence", 0.5))
            except (TypeError, ValueError):
                conf = 0.5
            cand = Candidate(
                refactored_code=code,
                explanation=item.get("explanation", ""),
                complexity_before=item.get("complexity_before", ""),
                complexity_after=item.get("complexity_after", ""),
                references=list(item.get("references", []) or []),
                confidence=max(0.0, min(1.0, conf)),
                benchmark_program=(item.get("benchmark_program") or "").strip(),
            )
            out.append(cand)
        return out, shared_bench

    @staticmethod
    def _candidate_bench(spec: dict, cand: Candidate) -> str:
        if cand.benchmark_program:
            return cand.benchmark_program
        return (spec.get("benchmark_program") or spec.get("benchmark_script") or "").strip()

    # Required by Agent ABC (unused for perf flow, which uses run_finding).
    def run(self, vuln, ctx):  # pragma: no cover -- interface compat
        raise NotImplementedError("RefactorAgent uses run_finding(PerfFinding, ...)")

    # ------------------------------------------------------------------
    @staticmethod
    def _slice_function(file_text: str, func_name: str, language: str) -> str:
        if not func_name:
            return ""
        if language == "python":
            try:
                tree = ast.parse(file_text)
            except SyntaxError:
                return ""
            lines = file_text.splitlines(keepends=True)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                    start = node.lineno - 1
                    end = (node.end_lineno or node.lineno)
                    return "".join(lines[start:end])
            return ""
        # Java / C#: brace-match from the first line mentioning the method name.
        return RefactorAgent._slice_braces(file_text, func_name)

    @staticmethod
    def _slice_braces(file_text: str, func_name: str) -> str:
        lines = file_text.splitlines(keepends=True)
        start_idx = None
        for i, ln in enumerate(lines):
            if func_name in ln and "(" in ln and ("{" in ln or ln.rstrip().endswith(")")):
                start_idx = i
                break
        if start_idx is None:
            return ""
        depth = 0
        seen_open = False
        out: list[str] = []
        for ln in lines[start_idx:]:
            out.append(ln)
            for ch in ln:
                if ch == "{":
                    depth += 1
                    seen_open = True
                elif ch == "}":
                    depth -= 1
            if seen_open and depth <= 0:
                break
        return "".join(out)

    @staticmethod
    def _code_valid(source: str, language: str) -> bool:
        if not source.strip():
            return False
        if language == "python":
            return RefactorAgent._is_python_valid(source)
        return RefactorAgent._braces_balanced(source)

    @staticmethod
    def _bench_valid(source: str, language: str) -> bool:
        if not source.strip():
            return False
        if language == "python":
            return RefactorAgent._is_python_valid(source) and "BENCH_RESULT" in source
        return RefactorAgent._braces_balanced(source) and "BENCH_RESULT" in source

    @staticmethod
    def _is_python_valid(source: str) -> bool:
        try:
            ast.parse(source)
            return True
        except SyntaxError as e:
            log.warning("refactor: python AST rejection: %s", e)
            return False

    @staticmethod
    def _braces_balanced(source: str) -> bool:
        # Lightweight structural check for Java/C#: braces and parens balance,
        # ignoring those inside string/char literals and line comments.
        depth_brace = depth_paren = 0
        in_str = in_char = in_line_comment = in_block_comment = False
        prev = ""
        for ch in source:
            if in_line_comment:
                if ch == "\n":
                    in_line_comment = False
                prev = ch
                continue
            if in_block_comment:
                if prev == "*" and ch == "/":
                    in_block_comment = False
                prev = ch
                continue
            if in_str:
                if ch == '"' and prev != "\\":
                    in_str = False
                prev = ch
                continue
            if in_char:
                if ch == "'" and prev != "\\":
                    in_char = False
                prev = ch
                continue
            if prev == "/" and ch == "/":
                in_line_comment = True
                prev = ch
                continue
            if prev == "/" and ch == "*":
                in_block_comment = True
                prev = ch
                continue
            if ch == '"':
                in_str = True
            elif ch == "'":
                in_char = True
            elif ch == "{":
                depth_brace += 1
            elif ch == "}":
                depth_brace -= 1
            elif ch == "(":
                depth_paren += 1
            elif ch == ")":
                depth_paren -= 1
            prev = ch
        return depth_brace == 0 and depth_paren == 0 and depth_brace >= 0
