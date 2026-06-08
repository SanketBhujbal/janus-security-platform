from __future__ import annotations

import pytest

from orchestrator.llm.canned import CANNED_EXPLOITS, CannedLLM


ATTACKER_SYS = "You are an offensive security engineer producing a SINGLE proof-of-concept exploit"
HEALER_SYS = "You are a senior secure-coding engineer"


def _user(category: str) -> str:
    return f"Vulnerability category: {category}\nSeverity: high\nTitle: x\n"


@pytest.mark.parametrize("category", sorted(CANNED_EXPLOITS))
def test_canned_returns_exploit_for_each_known_category(category):
    spec = CannedLLM().complete_json(ATTACKER_SYS, _user(category))
    assert "script" in spec and "EXPLOIT_SUCCESS" in spec["script"]
    assert "EXPLOIT_FAIL" in spec["script"]
    assert spec["payload"] and spec["expected_signal"]


def test_canned_refuses_unknown_category():
    with pytest.raises(RuntimeError, match="no canned exploit"):
        CannedLLM().complete_json(ATTACKER_SYS, _user("unknown_category"))


def test_canned_refuses_to_supply_patches():
    with pytest.raises(RuntimeError, match="no patches"):
        CannedLLM().complete_json(HEALER_SYS, _user("sql_injection"))


def test_canned_scripts_are_compilable_python():
    for category, spec in CANNED_EXPLOITS.items():
        compile(spec["script"], f"<canned:{category}>", "exec")
