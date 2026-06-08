from __future__ import annotations

import logging
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from pathlib import Path

import urllib.error
import urllib.request


log = logging.getLogger("security_brain.deployer")


class TargetDeployer(ABC):
    @abstractmethod
    def reload(self) -> bool:
        ...

    @abstractmethod
    def wait_ready(self, timeout_s: int = 60) -> bool:
        ...


class NullTargetDeployer(TargetDeployer):
    def reload(self) -> bool:
        return True

    def wait_ready(self, timeout_s: int = 60) -> bool:
        return True


class ComposeTargetDeployer(TargetDeployer):
    # Rebuilds + restarts a docker compose service so the validator replays
    # against the PATCHED code rather than the stale image. Required for
    # the self-healing loop to be honest.

    def __init__(
        self,
        compose_file: Path,
        service: str,
        health_url: str | None = None,
        compose_cmd: list[str] | None = None,
    ):
        if shutil.which("docker") is None:
            raise RuntimeError("docker not found in PATH")
        self.compose_file = compose_file.resolve()
        if not self.compose_file.exists():
            raise FileNotFoundError(self.compose_file)
        self.service = service
        self.health_url = health_url
        self.compose_cmd = compose_cmd or ["docker", "compose"]

    def reload(self) -> bool:
        cmd = [
            *self.compose_cmd,
            "-f", str(self.compose_file),
            "up", "-d", "--build", "--force-recreate", self.service,
        ]
        log.info("deployer: rebuilding %s via %s", self.service, " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            log.error(
                "deployer: rebuild failed (rc=%d) stderr=%s",
                result.returncode, result.stderr.strip(),
            )
            return False
        return True

    def wait_ready(self, timeout_s: int = 60) -> bool:
        if not self.health_url:
            return True
        deadline = time.monotonic() + timeout_s
        last_err: str = ""
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(self.health_url, timeout=2) as resp:
                    if 200 <= resp.status < 300:
                        return True
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
                last_err = str(e)
            time.sleep(1)
        log.warning("deployer: %s did not become ready (%s)", self.health_url, last_err)
        return False
