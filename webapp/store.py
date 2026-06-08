"""Persistent scan store.

Without this, scans live only in the ScanManager dict, so any restart
(deploy, code reload, crash) wipes them and any browser tab still pointing
at an old scan_id gets a 404 from /report. We write one JSON file per
completed scan into a workdir; the manager rehydrates from there on
startup and falls through to it on lookup.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


log = logging.getLogger("webapp.store")


@dataclass
class StoredScan:
    scan_id: str
    repo: str
    mode: str
    status: str          # "done" or "error"
    started_at: str = ""
    finished_at: str = ""
    error: str | None = None
    report: dict | None = None
    findings_index: dict | None = None

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "repo": self.repo,
            "mode": self.mode,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "report": self.report,
            "findings_index": self.findings_index,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "StoredScan":
        return cls(
            scan_id=d["scan_id"],
            repo=d.get("repo", ""),
            mode=d.get("mode", ""),
            status=d.get("status", ""),
            started_at=d.get("started_at", ""),
            finished_at=d.get("finished_at", ""),
            error=d.get("error"),
            report=d.get("report"),
            findings_index=d.get("findings_index"),
        )


class ScanStore:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, scan_id: str) -> Path:
        # scan_id is a hex string we generated; reject anything else so the
        # path can't escape the store directory.
        safe = "".join(c for c in scan_id if c.isalnum() or c in "-_")
        if not safe or safe != scan_id:
            raise ValueError(f"invalid scan_id: {scan_id!r}")
        return self.root / f"{safe}.json"

    def save(self, record: StoredScan) -> None:
        path = self._path(record.scan_id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(record.to_dict(), default=str), encoding="utf-8")
        tmp.replace(path)

    def load(self, scan_id: str) -> StoredScan | None:
        try:
            path = self._path(scan_id)
        except ValueError:
            return None
        if not path.exists():
            return None
        try:
            return StoredScan.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as e:
            log.warning("store: failed to load %s: %s", scan_id, e)
            return None

    def list_all(self) -> Iterable[StoredScan]:
        for f in sorted(self.root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                yield StoredScan.from_dict(json.loads(f.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError) as e:
                log.warning("store: skipping unreadable file %s: %s", f.name, e)
