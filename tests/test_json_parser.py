from __future__ import annotations

import json

import pytest

from orchestrator.llm.claude_client import _parse_json_payload


def test_plain_json():
    assert _parse_json_payload('{"a": 1}') == {"a": 1}


def test_fenced_json():
    raw = "```json\n{\"a\": 1, \"b\": [2,3]}\n```"
    assert _parse_json_payload(raw) == {"a": 1, "b": [2, 3]}


def test_unmarked_fenced_json():
    raw = "```\n{\"a\": 1}\n```"
    assert _parse_json_payload(raw) == {"a": 1}


def test_prose_around_json():
    raw = 'Sure, here is the response you asked for:\n\n{"payload": "x", "script": "print(1)"}\n\nLet me know if you need anything else!'
    out = _parse_json_payload(raw)
    assert out == {"payload": "x", "script": "print(1)"}


def test_nested_braces_in_json_strings():
    # Braces inside string literals must not confuse the balance walker.
    raw = '{"script": "print({\\"x\\": 1})", "ok": true}'
    out = _parse_json_payload(raw)
    assert out["ok"] is True
    assert "{" in out["script"]


def test_empty_response_raises():
    with pytest.raises(ValueError):
        _parse_json_payload("")


def test_no_json_raises():
    with pytest.raises(json.JSONDecodeError):
        _parse_json_payload("I cannot help with that request.")
