from __future__ import annotations

from pathlib import Path

from orchestrator.agents.attacker import AttackerAgent
from orchestrator.agents.base import AgentContext
from orchestrator.exploits.runner import SandboxResult
from orchestrator.models.vulnerability import (
    CodeLocation,
    FindingStatus,
    Severity,
    VulnCategory,
    Vulnerability,
)

from .fakes import FakeLLM, FakeSandbox


def _vuln(tmp_path: Path) -> Vulnerability:
    f = tmp_path / "vuln.py"
    f.write_text("def login():\n    pass\n", encoding="utf-8")
    return Vulnerability(
        category=VulnCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        title="SQLi in /login",
        description="Concat query",
        location=CodeLocation(file=f, start_line=1, end_line=2, snippet="def login():\n    pass\n"),
    )


def test_attacker_marks_exploited_when_sandbox_reports_success(tmp_path):
    llm = FakeLLM({
        "offensive security": {
            "payload": "' OR 1=1 --",
            "expected_signal": "auth bypass",
            "script": "print('EXPLOIT_SUCCESS: bypassed login')",
        }
    })
    sandbox = FakeSandbox(verdicts=[
        SandboxResult(exit_code=0, stdout="EXPLOIT_SUCCESS: bypassed login\n", stderr="")
    ])
    agent = AttackerAgent(llm, sandbox)
    ctx = AgentContext(repo_root=tmp_path, target_endpoint="http://t:8080")
    out = agent.run(_vuln(tmp_path), ctx)
    assert out.status == FindingStatus.EXPLOITED
    assert out.exploit is not None and out.exploit.succeeded is True
    assert out.exploitability == 1.0


def test_attacker_marks_discovered_when_sandbox_reports_failure(tmp_path):
    llm = FakeLLM({
        "offensive security": {
            "payload": "x",
            "expected_signal": "y",
            "script": "print('EXPLOIT_FAIL: nope')",
        }
    })
    sandbox = FakeSandbox(verdicts=[
        SandboxResult(exit_code=0, stdout="EXPLOIT_FAIL: nope\n", stderr="")
    ])
    agent = AttackerAgent(llm, sandbox)
    ctx = AgentContext(repo_root=tmp_path, target_endpoint="http://t:8080")
    out = agent.run(_vuln(tmp_path), ctx)
    assert out.status == FindingStatus.DISCOVERED
    assert out.exploit is not None and out.exploit.succeeded is False
    assert out.exploitability < 1.0
