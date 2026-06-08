"""Cross-run memory for the Security Brain.

Persists `{fingerprint -> last status, attempts, last_seen}` so subsequent runs
can skip findings that are already validated and avoid burning LLM tokens on
work that's already done. Stored as JSON next to the run report so it lives
with the project and can be reviewed by humans.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..models.vulnerability import FindingStatus, Vulnerability


log = logging.getLogger("security_brain.history")


@dataclass
class HistoryEntry:
    fingerprint: str
    status: str
    attempts: int = 0
    first_seen: str = ""
    last_seen: str = ""
    rule_id: str = ""
    location: str = ""
    category: str = ""


class FindingHistory:
    def __init__(self, path: Path):
        self.path = path
        self._entries: dict[str, HistoryEntry] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            log.warning("history: malformed file at %s (%s) — starting fresh", self.path, e)
            return
        for fp, payload in raw.items():
            self._entries[fp] = HistoryEntry(**payload)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        serialized = {fp: asdict(e) for fp, e in self._entries.items()}
        self.path.write_text(json.dumps(serialized, indent=2, sort_keys=True), encoding="utf-8")

    def should_skip(self, vuln: Vulnerability) -> bool:
        entry = self._entries.get(vuln.fingerprint)
        if entry is None:
            return False
        # We skip only findings already proven safe in a prior run. Anything
        # else (failed, discovered-only) is retried — maybe a new patch will
        # land.
        return entry.status == FindingStatus.VALIDATED.value

    def record(self, vuln: Vulnerability) -> None:
        fp = vuln.fingerprint
        now = datetime.now(timezone.utc).isoformat()
        existing = self._entries.get(fp)
        if existing is None:
            self._entries[fp] = HistoryEntry(
                fingerprint=fp,
                status=vuln.status.value,
                attempts=1,
                first_seen=now,
                last_seen=now,
                rule_id=vuln.rule_id or "",
                location=vuln.location.as_pointer(),
                category=vuln.category.value,
            )
        else:
            existing.status = vuln.status.value
            existing.attempts += 1
            existing.last_seen = now

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, fingerprint: str) -> bool:
        return fingerprint in self._entries
