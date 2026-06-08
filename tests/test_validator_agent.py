from __future__ import annotations

from pathlib import Path

from orchestrator.agents.base import AgentContext
from orchestrator.agents.validator import ValidatorAgent
from orchestrator.exploits.runner import SandboxResult
from orchestrator.models.vulnerability import (
    CodeLocation,
    Exploit,
    FindingStatus,
    Patch,
    Severity,
    VulnCategory,
    Vulnerability,
)

from .fakes import FakeDeployer, FakeLLM, FakeSandbox


def _patched_vuln(tmp_path: Path) -> Vulnerability:
    f = tmp_path / "code.py"
    f.write_text("ok = True\n", encoding="utf-8")
    v = Vulnerability(
        category=VulnCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        title="t",
        description="d",
        location=CodeLocation(file=f, start_line=1, end_line=1, snippet="ok = True"),
    )
    v.exploit = Exploit(
        category=VulnCategory.SQL_INJECTION,
        payload="x",
        script="print('replay')",
        succeeded=True,
        actual_signal="EXPLOIT_SUCCESS: bypass",
    )
    v.patch = Patch(
        location=v.location,
        original_code="ok = True\n",
        patched_code="ok = True  # patched\n",
        explanation="noop",
    )
    return v


def _passing_test_cmd() -> list[str]:
    # Cross-platform: python -c "exit(0)"
    import sys
    return [sys.executable, "-c", "raise SystemExit(0)"]


def _failing_test_cmd() -> list[str]:
    import sys
    return [sys.executable, "-c", "raise SystemExit(1)"]


def test_validator_passes_when_tests_pass_and_exploit_blocked(tmp_path):
    deployer = FakeDeployer()
    sandbox = FakeSandbox(verdicts=[
        SandboxResult(exit_code=0, stdout="EXPLOIT_FAIL: blocked by parameterized query", stderr="")
    ])
    agent = ValidatorAgent(
        FakeLLM({}), sandbox, test_command=_passing_test_cmd(), deployer=deployer,
    )
    out = agent.run(_patched_vuln(tmp_path), AgentContext(repo_root=tmp_path, target_endpoint="u"))
    assert out.status == FindingStatus.VALIDATED
    assert deployer.reloads == 1


def test_validator_fails_when_exploit_still_works(tmp_path):
    deployer = FakeDeployer()
    sandbox = FakeSandbox(verdicts=[
        SandboxResult(exit_code=0, stdout="EXPLOIT_SUCCESS: still bypassed", stderr="")
    ])
    agent = ValidatorAgent(
        FakeLLM({}), sandbox, test_command=_passing_test_cmd(), deployer=deployer,
    )
    out = agent.run(_patched_vuln(tmp_path), AgentContext(repo_root=tmp_path, target_endpoint="u"))
    assert out.status == FindingStatus.FAILED
    assert any("still succeeds" in n for n in out.notes)


def test_validator_fails_when_tests_break(tmp_path):
    deployer = FakeDeployer()
    sandbox = FakeSandbox()
    agent = ValidatorAgent(
        FakeLLM({}), sandbox, test_command=_failing_test_cmd(), deployer=deployer,
    )
    out = agent.run(_patched_vuln(tmp_path), AgentContext(repo_root=tmp_path, target_endpoint="u"))
    assert out.status == FindingStatus.FAILED
    assert any("tests failed" in n for n in out.notes)
    # Regression broke first — no point reloading the target.
    assert deployer.reloads == 0
    assert sandbox.calls == []


def test_validator_fails_when_target_redeploy_fails(tmp_path):
    deployer = FakeDeployer(reload_ok=False)
    sandbox = FakeSandbox()
    agent = ValidatorAgent(
        FakeLLM({}), sandbox, test_command=_passing_test_cmd(), deployer=deployer,
    )
    out = agent.run(_patched_vuln(tmp_path), AgentContext(repo_root=tmp_path, target_endpoint="u"))
    assert out.status == FindingStatus.FAILED
    assert any("redeploy failed" in n for n in out.notes)
    # Never got to replaying the exploit because deploy died first.
    assert sandbox.calls == []
