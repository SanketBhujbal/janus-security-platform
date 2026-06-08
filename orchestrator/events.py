"""Progress events emitted by the Security Brain.

The Brain calls `on_event(type, message, **data)` at every meaningful milestone.
The CLI uses the default no-op callback; the webapp passes a callback that
funnels events into an asyncio.Queue for SSE streaming.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Protocol


class EventCallback(Protocol):
    def __call__(self, type: str, message: str, **data: Any) -> None: ...


def noop_emitter(type: str, message: str, **data: Any) -> None:
    return None


# Canonical event types — keep this list authoritative; the frontend keys on
# these strings.
SCAN_START = "scan_start"
SCAN_FINDINGS_RAW = "scan_findings_raw"
SCAN_FINDINGS_PRIORITIZED = "scan_findings_prioritized"
FINDING_DISCOVERED = "finding_discovered"
FINDING_SKIPPED = "finding_skipped"
FINDING_COMPLETED = "finding_completed"
AGENT_START = "agent_start"
AGENT_DONE = "agent_done"
SCAN_DONE = "scan_done"
SCAN_ERROR = "scan_error"
PR_OPENED = "pr_opened"          # emitted when an autonomous PR is raised
CHAINS_DISCOVERED = "chains_discovered"  # HypothesisAgent found cross-finding chains


def make_event(type: str, message: str, **data: Any) -> dict:
    return {
        "type": type,
        "message": message,
        "ts": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
