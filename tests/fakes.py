"""Test doubles for the agents.

The agents depend on three external surfaces: an LLM, a Docker sandbox,
and a target deployer. Each is small enough to fake directly here, which
gives us deterministic end-to-end tests of the orchestrator loop without
network, API keys, or Docker.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from orchestrator.exploits.runner import SandboxResult
from orchestrator.llm.claude_client import LLMClient, LLMResponse
from orchestrator.sandbox.target_deployer import TargetDeployer


class FakeLLM(LLMClient):
    # Returns canned JSON keyed by a marker string found in the user prompt,
    # so a single fake can drive both Attacker and Healer in one test.

    def __init__(self, responses: dict[str, dict]):
        self.responses = responses
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str, *, max_tokens: int = 4096, temperature: float = 0.0):
        self.calls.append((system, user))
        return LLMResponse(text="{}", raw={})

    def complete_json(self, system: str, user: str, *, max_tokens: int = 4096) -> dict:
        self.calls.append((system, user))
        for marker, payload in self.responses.items():
            if marker in system or marker in user:
                return payload
        raise AssertionError(
            f"FakeLLM: no canned response matched. markers={list(self.responses)}"
        )


@dataclass
class FakeSandbox:
    # Drop-in for SandboxRunner. Doesn't need to subclass — duck typing is enough
    # since the agents only call run_python_exploit.
    verdicts: list[SandboxResult] = field(default_factory=list)
    calls: list[dict] = field(default_factory=list)
    on_call: Callable[[int, str], SandboxResult] | None = None

    def run_python_exploit(self, script: str, target_url: str, timeout_s: int = 30) -> SandboxResult:
        idx = len(self.calls)
        self.calls.append({"script": script, "target_url": target_url, "timeout_s": timeout_s})
        if self.on_call is not None:
            return self.on_call(idx, script)
        if idx < len(self.verdicts):
            return self.verdicts[idx]
        return SandboxResult(exit_code=0, stdout="EXPLOIT_FAIL: no canned verdict", stderr="")


@dataclass
class FakeDeployer(TargetDeployer):
    reload_ok: bool = True
    ready_ok: bool = True
    reloads: int = 0

    def reload(self) -> bool:
        self.reloads += 1
        return self.reload_ok

    def wait_ready(self, timeout_s: int = 60) -> bool:
        return self.ready_ok
