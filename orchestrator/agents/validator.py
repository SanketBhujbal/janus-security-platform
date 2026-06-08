from __future__ import annotations

import subprocess
from pathlib import Path

from ..exploits.runner import SandboxRunner
from ..llm.claude_client import LLMClient
from ..models.vulnerability import FindingStatus, Vulnerability
from ..sandbox.target_deployer import NullTargetDeployer, TargetDeployer
from .base import Agent, AgentContext


class ValidatorAgent(Agent):
    name = "validator"

    def __init__(
        self,
        llm: LLMClient,
        sandbox: SandboxRunner,
        test_command: list[str] | None = None,
        deployer: TargetDeployer | None = None,
    ):
        super().__init__(llm)
        self.sandbox = sandbox
        self.test_command = test_command or ["pytest", "-q"]
        self.deployer = deployer or NullTargetDeployer()

    def run(self, vuln: Vulnerability, ctx: AgentContext) -> Vulnerability:
        if vuln.patch is None:
            vuln.notes.append("validator: no patch to validate")
            return vuln

        tests_ok = self._run_tests(ctx.repo_root)
        if not tests_ok:
            vuln.status = FindingStatus.FAILED
            vuln.notes.append("validator: tests failed after patch")
            return vuln

        if vuln.exploit is None:
            vuln.status = FindingStatus.VALIDATED
            vuln.notes.append("validator: tests passed; no exploit to replay")
            return vuln

        if not self.deployer.reload():
            vuln.status = FindingStatus.FAILED
            vuln.notes.append("validator: target redeploy failed — cannot verify fix")
            return vuln
        if not self.deployer.wait_ready(timeout_s=60):
            vuln.status = FindingStatus.FAILED
            vuln.notes.append("validator: target did not become healthy after redeploy")
            return vuln

        replay = self.sandbox.run_python_exploit(
            script=vuln.exploit.script,
            target_url=ctx.target_endpoint or "",
            timeout_s=30,
        )
        exploit_blocked = "EXPLOIT_SUCCESS" not in replay.stdout
        if exploit_blocked:
            vuln.status = FindingStatus.VALIDATED
            vuln.notes.append("validator: tests pass AND exploit no longer reproduces")
        else:
            vuln.status = FindingStatus.FAILED
            vuln.notes.append("validator: exploit still succeeds after patch — fix rejected")
        return vuln

    def _run_tests(self, repo_root: Path) -> bool:
        result = subprocess.run(
            self.test_command,
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0
