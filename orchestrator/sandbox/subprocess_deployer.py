"""Subprocess-based target deployer.

For demos without Docker. Starts the target service (e.g. our seeded Flask
app) as a host Python subprocess and stops/restarts it as the validator
requests. The validator uses reload() between patch and exploit replay so
the patched source is what gets re-attacked.

Process lifecycle:
  - First reload() spawns the target.
  - Subsequent reload()s kill ANY process listening on the target's port
    (including stragglers from previous deployer instances), then spawn fresh.
  - On orchestrator shutdown (process exit) the OS reclaims the child.

Limitations vs Docker:
  - No network isolation. Target listens on host loopback.
  - No filesystem isolation. Target sees the real disk.
  - Single instance per port -- no parallel targets without per-instance port.
"""
from __future__ import annotations

import logging
import os
import platform
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .target_deployer import TargetDeployer


log = logging.getLogger("security_brain.subprocess_deployer")


class SubprocessTargetDeployer(TargetDeployer):
    def __init__(
        self,
        target_script: Path | None = None,
        health_url: str | None = None,
        python_executable: str | None = None,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        startup_seconds: float = 0.5,
        command: list[str] | None = None,
    ):
        # Two launch modes:
        #   - target_script (Python): we run `<python> <script>`.
        #   - command (anything else, e.g. `dotnet run --project <dir>`): we run
        #     the command verbatim. `cwd` is required-ish for build tools.
        # Exactly one of the two must be supplied.
        self.command = list(command) if command else None
        if self.command is None:
            if target_script is None:
                raise ValueError("SubprocessTargetDeployer needs either command or target_script")
            self.target_script = target_script.resolve()
            if not self.target_script.exists():
                raise FileNotFoundError(self.target_script)
            self.cwd = (cwd or self.target_script.parent).resolve()
        else:
            self.target_script = None
            self.cwd = (cwd or Path.cwd()).resolve()
        self.health_url = health_url
        self.python = python_executable or sys.executable
        self.env = env
        self.startup_seconds = startup_seconds
        self._proc: subprocess.Popen[str] | None = None

    def reload(self) -> bool:
        # Kill the previous instance we tracked AND any orphan listening on
        # the same port (e.g. a Flask from a previous scan whose deployer
        # instance is long gone). Without the second step, a stale process
        # keeps serving in-memory patched code while the file on disk has
        # been reverted, and exploits get unexpected responses.
        self._terminate_existing()
        port = self._port_from_health_url()
        if port is not None:
            killed = self._kill_listeners_on_port(port)
            if killed:
                log.info("subprocess_deployer: killed %d orphan process(es) on port %d", killed, port)
                # Give the OS a moment to release the socket.
                time.sleep(0.5)
        cmd = self.command if self.command is not None else [self.python, str(self.target_script)]
        log.info("subprocess_deployer: launching %s (cwd=%s)", " ".join(cmd), self.cwd)
        env = {**os.environ, **(self.env or {})}
        # Custom commands (e.g. `dotnet run`) can emit a lot of build/server
        # output. If we PIPE stdout and never drain it, a full OS pipe buffer
        # would block the child. We only need stderr for failure diagnostics,
        # so discard stdout for command mode. The Python path stays on PIPE.
        stdout_target = subprocess.DEVNULL if self.command is not None else subprocess.PIPE
        try:
            self._proc = subprocess.Popen(
                cmd,
                cwd=str(self.cwd),
                env=env,
                stdout=stdout_target,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as e:
            log.error("subprocess_deployer: failed to spawn target: %s", e)
            return False
        # Give the process a moment to bind its port before we start polling
        # health -- Flask is ~200ms cold; `dotnet run` needs longer (build + JIT).
        time.sleep(self.startup_seconds)
        return True

    def wait_ready(self, timeout_s: int = 60) -> bool:
        if not self.health_url:
            return True
        deadline = time.monotonic() + timeout_s
        last_err = ""
        while time.monotonic() < deadline:
            # Bail early if the process already died on startup.
            if self._proc is not None and self._proc.poll() is not None:
                stderr = (self._proc.stderr.read() if self._proc.stderr else "") or ""
                log.error(
                    "subprocess_deployer: target exited rc=%d stderr-tail=%s",
                    self._proc.returncode, stderr[-500:],
                )
                return False
            try:
                with urllib.request.urlopen(self.health_url, timeout=2) as resp:
                    if 200 <= resp.status < 300:
                        return True
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionError) as e:
                last_err = str(e)
            time.sleep(0.3)
        log.warning("subprocess_deployer: %s did not become ready (%s)", self.health_url, last_err)
        return False

    def _terminate_existing(self) -> None:
        if self._proc is None:
            return
        if self._proc.poll() is not None:
            # Already exited; nothing to do.
            self._proc = None
            return
        log.info("subprocess_deployer: terminating previous PID %s", self._proc.pid)
        try:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=2)
        except Exception as e:
            log.warning("subprocess_deployer: terminate failed: %s", e)
        self._proc = None

    def stop(self) -> None:
        self._terminate_existing()

    def _port_from_health_url(self) -> int | None:
        if not self.health_url:
            return None
        try:
            return urllib.parse.urlparse(self.health_url).port
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def _kill_listeners_on_port(port: int) -> int:
        # Cross-platform "kill anything listening on this TCP port" without
        # adding a psutil dependency. Returns the number of PIDs we killed.
        if platform.system() == "Windows":
            return _kill_listeners_windows(port)
        return _kill_listeners_unix(port)


def _kill_listeners_windows(port: int) -> int:
    # netstat -ano -> filter LISTENING rows for :PORT -> taskkill /F /PID.
    try:
        out = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        log.warning("subprocess_deployer: netstat failed: %s", e)
        return 0
    pids: set[str] = set()
    needle = f":{port} "
    for line in out.stdout.splitlines():
        # Lines look like:  TCP    0.0.0.0:8080    0.0.0.0:0   LISTENING   12345
        if needle not in line or "LISTENING" not in line:
            continue
        parts = line.split()
        if parts and parts[-1].isdigit():
            pid = parts[-1]
            if pid != "0":
                pids.add(pid)
    killed = 0
    for pid in pids:
        try:
            r = subprocess.run(
                ["taskkill", "/F", "/PID", pid],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if r.returncode == 0:
                killed += 1
            else:
                log.warning("subprocess_deployer: taskkill PID %s rc=%d %s",
                            pid, r.returncode, r.stderr.strip())
        except (OSError, subprocess.TimeoutExpired) as e:
            log.warning("subprocess_deployer: taskkill PID %s failed: %s", pid, e)
    return killed


def _kill_listeners_unix(port: int) -> int:
    # Prefer lsof (consistent across linux+mac). Falls back silently if not present.
    try:
        out = subprocess.run(
            ["lsof", "-ti", f"tcp:{port}", "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        log.warning("subprocess_deployer: lsof failed: %s", e)
        return 0
    pids = [p for p in out.stdout.split() if p.isdigit()]
    killed = 0
    for pid in pids:
        try:
            os.kill(int(pid), signal.SIGKILL)
            killed += 1
        except (OSError, ProcessLookupError) as e:
            log.warning("subprocess_deployer: kill -9 %s failed: %s", pid, e)
    return killed
