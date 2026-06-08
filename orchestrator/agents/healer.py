from __future__ import annotations

import ast
import logging
import re
import textwrap
from pathlib import Path

from ..models.vulnerability import (
    CodeLocation,
    FileEdit,
    FindingStatus,
    Patch,
    Vulnerability,
)
from .base import Agent, AgentContext


log = logging.getLogger("security_brain.healer")


HEALER_SYSTEM = """You are a senior secure-coding engineer. Given a vulnerability and the surrounding \
source code, produce a minimal, correct patch that eliminates the vulnerability while preserving \
behavior. Follow OWASP Top 10 and PCI DSS guidance for payments code.

Constraints:
- Do NOT add new third-party dependencies unless absolutely required.
- Prefer: parameterized queries, server-side validation, idempotency keys (Idempotency-Key header + \
  persistent dedup table), strict typing on monetary values, structured logging with explicit masking \
  of PAN/CVV/track data, and server-side reconciliation against trusted order/price records.
- Do NOT modify unrelated code.
- The "patched_code" you return REPLACES exactly the source lines start_line..end_line provided. \
  Keep indentation consistent with the original snippet.
- CRITICAL — the result MUST COMPILE. Use only symbols that are actually in scope at the patch \
  location. Read the surrounding-file context provided below to confirm which variables, parameters, \
  fields, helper methods, and request/logger/db objects truly exist. Do NOT invent helpers (e.g. a \
  MaskPan() that isn't defined), do NOT reference parameters the enclosing function/handler/lambda \
  does not declare, and do NOT access fields a class does not have. If your fix genuinely needs a new \
  helper method, a new field, or a new handler parameter, EITHER inline the logic so no new symbol is \
  required, OR add the supporting definition via an "extra_edits" entry that targets the correct lines \
  of the same file. When unsure, prefer the smallest self-contained edit that closes the vulnerability.

Some fixes genuinely require changes to more than one file (e.g. adding a security filter class, \
updating a configuration bean, patching a companion test file). Use "extra_edits" for those. Each \
entry replaces lines start_line..end_line in the given file (relative_path is relative to the repo \
root, always forward slashes). Set extra_edits to [] when no additional files need changing.

Respond with STRICT JSON only (no prose, no fences):
{
  "patched_code": "<full replacement for the vulnerable snippet>",
  "extra_edits": [
    {
      "relative_path": "<path relative to repo root, forward slashes>",
      "start_line": <int>,
      "end_line": <int>,
      "patched_code": "<replacement for those exact lines>"
    }
  ],
  "explanation": "<2-4 sentences on why this fixes it>",
  "references": ["OWASP A03:2021", "PCI DSS 6.5.1"]
}
"""


class HealerAgent(Agent):
    name = "healer"

    def run(self, vuln: Vulnerability, ctx: AgentContext) -> Vulnerability:
        if vuln.exploit is None or not vuln.exploit.succeeded:
            vuln.notes.append("healer: skipped (no confirmed exploit)")
            return vuln

        # Findings are detected against the original file, but patches are
        # applied sequentially in this run — every prior edit shifts the line
        # numbers of every later finding. Re-locate this finding by its
        # scan-time snippet before we read or replace anything, so we never
        # patch drifted line numbers. If the snippet can no longer be found,
        # an earlier patch already rewrote this region; skip rather than emit
        # a conflicting/garbled patch (and don't waste an LLM call on it).
        if not self._reanchor_location(vuln.location):
            vuln.status = FindingStatus.FAILED
            vuln.notes.append(
                "healer: target region was already modified by an earlier patch "
                "in this run — skipped to avoid a conflicting patch"
            )
            return vuln

        original = self._read_snippet(vuln.location)
        # Give the healer the same whole-file visibility the attacker gets, so
        # its patch references only symbols that actually exist (parameters,
        # fields, helpers, logger/db/request objects) and therefore compiles.
        file_excerpt = self._read_file_excerpt(vuln.location.file, max_chars=6000)
        # Also include files that call / depend on the patched code so the
        # healer knows which signatures and contracts must not be broken.
        caller_context = self._find_caller_context(vuln, ctx)
        spec = self.llm.complete_json(
            HEALER_SYSTEM,
            textwrap.dedent(
                f"""
                Vulnerability: {vuln.category.value} ({vuln.severity.value})
                Title: {vuln.title}
                Description: {vuln.description}
                Location: {vuln.location.as_pointer()} (lines {vuln.location.start_line}..{vuln.location.end_line})
                Successful exploit payload: {vuln.exploit.payload}
                Exploit evidence: {vuln.exploit.actual_signal}

                Original code (this is the exact snippet your "patched_code" replaces):
                ---
                {original}
                ---

                Surrounding file context (READ-ONLY — for understanding what is in
                scope; do NOT return this, only return the replacement snippet):
                ---
                {file_excerpt}
                ---
                {caller_context}"""
            ).strip(),
        )

        extra_edits = self._parse_extra_edits(spec, ctx)

        patch = Patch(
            location=vuln.location,
            original_code=original,
            patched_code=spec["patched_code"],
            explanation=spec.get("explanation", ""),
            references=spec.get("references", []),
            extra_edits=extra_edits,
        )
        if not self._apply_patch_safely(patch):
            vuln.status = FindingStatus.FAILED
            vuln.notes.append("healer: patch rejected (syntax check failed); file(s) unchanged")
            return vuln
        n_extra = len(extra_edits)
        vuln.patch = patch
        vuln.status = FindingStatus.PATCHED
        vuln.notes.append(
            f"healer: patch applied ({1 + n_extra} file(s) edited)"
            if n_extra else "healer: patch applied"
        )
        return vuln

    def _parse_extra_edits(self, spec: dict, ctx: AgentContext) -> list[FileEdit]:
        """Resolve and validate extra_edits returned by the LLM."""
        repo_root = ctx.repo_root.resolve()
        edits: list[FileEdit] = []
        for raw in spec.get("extra_edits") or []:
            rel = (raw.get("relative_path") or "").strip()
            if not rel:
                continue
            # Path-traversal guard: resolved path must stay inside repo root.
            try:
                target = (repo_root / rel).resolve()
                target.relative_to(repo_root)
            except (ValueError, OSError):
                log.warning("healer: extra_edit path escapes repo or is invalid: %r — skipped", rel)
                continue
            if not target.exists():
                log.warning("healer: extra_edit file not found: %r — skipped", rel)
                continue
            try:
                start = int(raw.get("start_line") or 0)
                end = int(raw.get("end_line") or start)
            except (TypeError, ValueError):
                log.warning("healer: extra_edit has non-integer line range in %r — skipped", rel)
                continue
            if start < 1 or end < start:
                log.warning("healer: extra_edit bad line range %d..%d in %r — skipped", start, end, rel)
                continue
            try:
                orig_lines = target.read_text(encoding="utf-8").splitlines(keepends=True)
                orig = "".join(orig_lines[start - 1 : end])
            except OSError:
                orig = ""
            edits.append(FileEdit(
                file=target,
                start_line=start,
                end_line=end,
                original_code=orig,
                patched_code=raw.get("patched_code") or "",
            ))
        return edits

    def _reanchor_location(self, loc: CodeLocation) -> bool:
        """Re-locate ``loc`` against the CURRENT file by its scan-time snippet.

        Mutates ``loc.start_line``/``end_line`` in place when line drift is
        detected and the snippet can be uniquely re-located.

        Returns True when ``loc`` points at the right code — either because the
        recorded lines still match (no drift) or because we re-anchored them.
        Returns False when the snippet can no longer be found, which means an
        earlier patch in this run already rewrote that region; patching the
        stale line range would produce garbage, so the caller should skip.

        Findings without a snippet (e.g. imported SARIF/Checkmarx results)
        can't be re-anchored — we trust their line numbers and return True.
        """
        if not loc.snippet.strip():
            return True
        try:
            file_lines = loc.file.read_text(encoding="utf-8").splitlines()
        except OSError:
            return True  # let the normal read path surface the error

        # Match on non-blank, whitespace-stripped lines so re-indentation and
        # blank-line changes from earlier patches don't defeat the lookup.
        snippet_norm = [ln.strip() for ln in loc.snippet.splitlines() if ln.strip()]
        if not snippet_norm:
            return True

        current = [
            ln.strip()
            for ln in file_lines[loc.start_line - 1 : loc.end_line]
            if ln.strip()
        ]
        if current == snippet_norm:
            return True  # no drift — recorded lines still match

        # Search every non-blank line window for the snippet sequence. Carry
        # each non-blank line's 1-based file line number so we can report the
        # true current range.
        indexed = [(i + 1, ln.strip()) for i, ln in enumerate(file_lines) if ln.strip()]
        n = len(snippet_norm)
        matches = [
            (indexed[s][0], indexed[s + n - 1][0])
            for s in range(len(indexed) - n + 1)
            if [t[1] for t in indexed[s : s + n]] == snippet_norm
        ]
        if len(matches) == 1:
            new_start, new_end = matches[0]
            log.info(
                "healer: re-anchored %s snippet %d..%d -> %d..%d (line drift corrected)",
                loc.file.name, loc.start_line, loc.end_line, new_start, new_end,
            )
            loc.start_line, loc.end_line = new_start, new_end
            return True

        log.warning(
            "healer: snippet at %s no longer locatable (%d candidate match(es)) — "
            "an earlier patch likely rewrote this region; skipping to avoid a "
            "conflicting patch",
            loc.file.name, len(matches),
        )
        return False

    def _read_snippet(self, loc: CodeLocation) -> str:
        lines = loc.file.read_text(encoding="utf-8").splitlines(keepends=True)
        return "".join(lines[loc.start_line - 1 : loc.end_line])

    @staticmethod
    def _read_file_excerpt(path, max_chars: int = 6000) -> str:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "(could not read file)"
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + f"\n... (file truncated, {len(text) - max_chars} chars omitted)"

    def _find_caller_context(self, vuln: Vulnerability, ctx: AgentContext) -> str:
        """Return excerpts from files that call / import the patched code.

        Helps the healer avoid breaking callers' expectations (signatures,
        return types, error codes). Returns an empty string when nothing useful
        is found — the main patch prompt already covers the common case.
        """
        # Extract candidate symbol names from the vulnerable snippet. We look
        # for: Python defs, C# method/class names, Java method names.
        snippet = vuln.location.snippet or ""
        names: list[str] = []
        for pattern in (
            r"\bdef\s+(\w{3,})\b",           # Python function
            r"\bclass\s+(\w{3,})\b",          # Python / Java / C# class
            r"\bvoid\s+(\w{3,})\s*\(",        # Java / C# void method
            r"\b(\w{3,})\s*\([^)]*\)\s*\{",  # C# / Java method body open
            r"app\.Map\w+\(\s*\"(/[^\"]+)\"", # ASP.NET route path
        ):
            for m in re.finditer(pattern, snippet):
                candidate = m.group(1)
                if len(candidate) >= 3 and candidate not in names:
                    names.append(candidate)
            if len(names) >= 3:
                break

        if not names:
            return ""

        callers: list[str] = []
        seen: set[Path] = {vuln.location.file.resolve()}
        extensions = ("*.py", "*.cs", "*.java", "*.ts", "*.js")
        try:
            for ext in extensions:
                for candidate_file in ctx.repo_root.rglob(ext):
                    if candidate_file.resolve() in seen:
                        continue
                    try:
                        text = candidate_file.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    if any(name in text for name in names):
                        seen.add(candidate_file.resolve())
                        rel = candidate_file.relative_to(ctx.repo_root)
                        excerpt = text if len(text) <= 3000 else text[:3000] + "...(truncated)"
                        callers.append(f"// {rel}\n{excerpt}")
                        if len(callers) >= 2:
                            break
                if len(callers) >= 2:
                    break
        except Exception as exc:
            log.debug("healer: caller context search failed: %s", exc)

        if not callers:
            return ""

        joined = "\n---\n".join(callers)
        return (
            f"\nCaller / dependent files (READ-ONLY — ensure your patch does NOT "
            f"break the contracts these files rely on):\n---\n{joined}\n---\n"
        )

    def _apply_patch_safely(self, patch: Patch) -> bool:
        # Build all candidate file contents in memory first, validate all, then
        # write all. On any validation failure nothing is written (fail-safe).
        edits: list[tuple] = [
            (patch.location.file, patch.location.start_line, patch.location.end_line, patch.patched_code),
        ]
        for e in patch.extra_edits:
            edits.append((e.file, e.start_line, e.end_line, e.patched_code))

        candidates: list[tuple] = []
        for target, start, end, new_code in edits:
            try:
                lines = target.read_bytes().decode("utf-8").splitlines(keepends=True)
            except (OSError, UnicodeDecodeError) as exc:
                log.warning("healer: cannot read %s: %s", target, exc)
                return False
            if not new_code.endswith("\n"):
                new_code += "\n"
            candidate = "".join(lines[: start - 1]) + new_code + "".join(lines[end :])
            if not self._is_syntactically_valid(target.name, candidate):
                log.warning(
                    "healer: rejected patch for %s — candidate fails syntax check", target
                )
                return False
            candidates.append((target, candidate))

        for target, content in candidates:
            target.write_text(content, encoding="utf-8")
            log.info("healer: wrote %s", target)
        return True

    @staticmethod
    def _is_syntactically_valid(filename: str, source: str) -> bool:
        if filename.endswith(".py"):
            try:
                ast.parse(source, filename=filename)
                return True
            except SyntaxError as e:
                log.warning("healer: python syntax error: %s", e)
                return False
        return True
