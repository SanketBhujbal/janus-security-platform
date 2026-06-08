from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..llm.claude_client import LLMClient
from ..models.vulnerability import Vulnerability


@dataclass
class AgentContext:
    repo_root: Path
    target_endpoint: str | None = None
    sandbox_network: str = "security-orchestrator-sandbox"
    workdir: Path = field(default_factory=lambda: Path("./.security_workdir"))
    metadata: dict[str, Any] = field(default_factory=dict)


class Agent(ABC):
    name: str = "agent"

    def __init__(self, llm: LLMClient):
        self.llm = llm

    @abstractmethod
    def run(self, vuln: Vulnerability, ctx: AgentContext) -> Vulnerability:
        ...
