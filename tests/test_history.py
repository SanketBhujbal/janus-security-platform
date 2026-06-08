from __future__ import annotations

from pathlib import Path

from orchestrator.models.vulnerability import (
    CodeLocation,
    FindingStatus,
    Severity,
    VulnCategory,
    Vulnerability,
)
from orchestrator.state.history import FindingHistory


def _v(tmp: Path, category: VulnCategory = VulnCategory.SQL_INJECTION) -> Vulnerability:
    return Vulnerability(
        category=category,
        severity=Severity.HIGH,
        title="t",
        description="d",
        location=CodeLocation(file=tmp / "x.py", start_line=10, end_line=12, snippet=""),
        rule_id="some.rule",
    )


def test_history_skips_only_validated_findings(tmp_path):
    h = FindingHistory(tmp_path / "hist.json")
    v = _v(tmp_path)
    assert not h.should_skip(v)
    v.status = FindingStatus.EXPLOITED
    h.record(v)
    assert not h.should_skip(v)  # exploited but not validated -> retry next run
    v.status = FindingStatus.VALIDATED
    h.record(v)
    assert h.should_skip(v)


def test_history_persists_and_reloads(tmp_path):
    path = tmp_path / "hist.json"
    h1 = FindingHistory(path)
    v = _v(tmp_path)
    v.status = FindingStatus.VALIDATED
    h1.record(v)
    h1.save()
    assert path.exists()

    h2 = FindingHistory(path)
    assert v.fingerprint in h2
    assert h2.should_skip(v)


def test_history_counts_attempts(tmp_path):
    h = FindingHistory(tmp_path / "hist.json")
    v = _v(tmp_path)
    h.record(v)
    h.record(v)
    h.record(v)
    assert h._entries[v.fingerprint].attempts == 3


def test_history_survives_corrupt_file(tmp_path):
    path = tmp_path / "hist.json"
    path.write_text("{this is not json", encoding="utf-8")
    h = FindingHistory(path)
    assert len(h) == 0
