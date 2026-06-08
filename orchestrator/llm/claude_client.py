from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None  # type: ignore[assignment]


DEFAULT_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
DEFAULT_MAX_TOKENS = 4096


@dataclass
class LLMResponse:
    text: str
    raw: dict
    input_tokens: int = 0
    output_tokens: int = 0


class LLMClient:
    def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.0,
    ) -> LLMResponse:
        raise NotImplementedError

    def complete_json(self, system: str, user: str, *, max_tokens: int = DEFAULT_MAX_TOKENS) -> dict:
        resp = self.complete(system, user, max_tokens=max_tokens)
        return _parse_json_payload(resp.text)


class ClaudeClient(LLMClient):
    def __init__(self, model: str = DEFAULT_MODEL, api_key: Optional[str] = None):
        if Anthropic is None:
            raise RuntimeError("anthropic SDK not installed. pip install anthropic")
        self.model = model
        self.client = Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))

    def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.0,
    ) -> LLMResponse:
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(
            getattr(block, "text", "")
            for block in resp.content
            if getattr(block, "type", "") == "text"
        )
        return LLMResponse(
            text=text,
            raw=resp.model_dump() if hasattr(resp, "model_dump") else {},
            input_tokens=getattr(resp.usage, "input_tokens", 0),
            output_tokens=getattr(resp.usage, "output_tokens", 0),
        )


def _parse_json_payload(text: str) -> dict:
    # LLMs sometimes add prose around the JSON ("Here's the JSON: { ... }")
    # or wrap it in ``` fences, or split thinking + JSON across blocks. Be
    # tolerant: try the strict path first, then fall back to extracting the
    # outermost { ... } balanced object from anywhere in the text.
    text = text.strip()
    if not text:
        raise ValueError("LLM returned empty response")
    stripped = text
    if stripped.startswith("```"):
        stripped = stripped.split("```", 2)[1]
        if stripped.startswith("json"):
            stripped = stripped[4:]
        stripped = stripped.strip()
        if stripped.endswith("```"):
            stripped = stripped[:-3].strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    extracted = _extract_balanced_json(text)
    if extracted is None:
        # Surface the original text in the error so callers can debug what
        # the LLM actually said. Cap to keep logs reasonable.
        raise json.JSONDecodeError(
            f"no JSON object found in LLM response (got {len(text)} chars; "
            f"head={text[:200]!r})",
            text, 0,
        )
    return json.loads(extracted)


def _extract_balanced_json(text: str) -> str | None:
    # Walk the string, find the first '{', then track brace depth (ignoring
    # braces inside strings) until depth returns to 0. Returns the substring
    # of that balanced object, or None if no valid balanced object exists.
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None
