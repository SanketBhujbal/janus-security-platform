from __future__ import annotations

from pathlib import Path

from orchestrator.agents.base import AgentContext
from orchestrator.agents.healer import HealerAgent
from orchestrator.models.vulnerability import (
    CodeLocation,
    Exploit,
    FindingStatus,
    Severity,
    VulnCategory,
    Vulnerability,
)

from .fakes import FakeLLM


SOURCE_BEFORE = (
    "def login(u, p):\n"
    "    q = f\"SELECT * FROM users WHERE u='{u}' AND p='{p}'\"\n"
    "    return db.execute(q)\n"
)


def _seed(tmp_path: Path) -> Vulnerability:
    f = tmp_path / "auth.py"
    f.write_text(SOURCE_BEFORE, encoding="utf-8")
    vuln = Vulnerability(
        category=VulnCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        title="SQLi",
        description="concat query",
        location=CodeLocation(
            file=f, start_line=2, end_line=2,
            snippet="    q = f\"SELECT * FROM users WHERE u='{u}' AND p='{p}'\"",
        ),
    )
    vuln.exploit = Exploit(
        category=VulnCategory.SQL_INJECTION,
        payload="' OR 1=1 --",
        script="print('EXPLOIT_SUCCESS')",
        succeeded=True,
        actual_signal="EXPLOIT_SUCCESS: bypass",
    )
    return vuln


def test_healer_applies_patch_to_correct_lines(tmp_path):
    llm = FakeLLM({
        "secure-coding": {
            "patched_code": "    q = \"SELECT * FROM users WHERE u=? AND p=?\"\n    return db.execute(q, (u, p))",
            "explanation": "Parameterized query.",
            "references": ["OWASP A03:2021"],
        }
    })
    agent = HealerAgent(llm)
    vuln = _seed(tmp_path)
    out = agent.run(vuln, AgentContext(repo_root=tmp_path))
    assert out.status == FindingStatus.PATCHED
    new = (tmp_path / "auth.py").read_text(encoding="utf-8")
    # Original line 2 is gone, parameterized version replaces it, line 1 and 3 preserved.
    assert "f\"SELECT" not in new
    assert "db.execute(q, (u, p))" in new
    assert new.splitlines()[0] == "def login(u, p):"


def test_healer_rejects_patch_that_breaks_python_syntax(tmp_path):
    llm = FakeLLM({
        "secure-coding": {
            "patched_code": "    q = ???not python",  # deliberately broken
            "explanation": "bad",
            "references": [],
        }
    })
    vuln = _seed(tmp_path)
    before = (tmp_path / "auth.py").read_text(encoding="utf-8")
    out = HealerAgent(llm).run(vuln, AgentContext(repo_root=tmp_path))
    assert out.status == FindingStatus.FAILED
    assert out.patch is None
    # File was NOT modified — original code preserved.
    assert (tmp_path / "auth.py").read_text(encoding="utf-8") == before


def test_healer_reanchors_after_line_drift(tmp_path):
    # Simulate an earlier patch in the same run having inserted lines above the
    # finding: the file shifts but vuln.location still holds the scan-time line
    # numbers. The healer must re-locate the snippet and patch the RIGHT line.
    llm = FakeLLM({
        "secure-coding": {
            "patched_code": "    q = \"SELECT * FROM users WHERE u=? AND p=?\"\n    return db.execute(q, (u, p))",
            "explanation": "Parameterized query.",
            "references": ["OWASP A03:2021"],
        }
    })
    vuln = _seed(tmp_path)            # snippet recorded at line 2
    f = tmp_path / "auth.py"
    f.write_text("# inserted by an earlier patch\n# another inserted line\n" + SOURCE_BEFORE,
                 encoding="utf-8")    # snippet is now at line 4, location still says 2

    out = HealerAgent(llm).run(vuln, AgentContext(repo_root=tmp_path))

    assert out.status == FindingStatus.PATCHED
    # Re-anchored to the true current location.
    assert vuln.location.start_line == 4 and vuln.location.end_line == 4
    new = f.read_text(encoding="utf-8")
    assert "f\"SELECT" not in new                       # vulnerable line replaced
    assert "db.execute(q, (u, p))" in new               # fix landed
    assert new.splitlines()[0] == "# inserted by an earlier patch"  # inserted lines preserved
    assert "def login(u, p):" in new                    # surrounding code intact


def test_healer_skips_when_region_already_rewritten(tmp_path):
    # An earlier patch rewrote the vulnerable region, so the scan-time snippet
    # no longer exists. The healer must skip cleanly (not patch garbage) and
    # must not even call the LLM.
    llm = FakeLLM({
        "secure-coding": {
            "patched_code": "    q = \"safe\"",
            "explanation": "x",
            "references": [],
        }
    })
    vuln = _seed(tmp_path)
    f = tmp_path / "auth.py"
    rewritten = (
        "def login(u, p):\n"
        "    q = build_query(u, p)  # already fixed by a prior patch\n"
        "    return db.execute(q)\n"
    )
    f.write_text(rewritten, encoding="utf-8")

    out = HealerAgent(llm).run(vuln, AgentContext(repo_root=tmp_path))

    assert out.status == FindingStatus.FAILED
    assert out.patch is None
    assert any("already modified by an earlier patch" in n for n in out.notes)
    assert llm.calls == []                                  # no wasted LLM call
    assert f.read_text(encoding="utf-8") == rewritten       # file untouched


def test_healer_skips_when_exploit_did_not_reproduce(tmp_path):
    llm = FakeLLM({"secure-coding": {"patched_code": "x", "explanation": "y", "references": []}})
    vuln = _seed(tmp_path)
    vuln.exploit.succeeded = False
    out = HealerAgent(llm).run(vuln, AgentContext(repo_root=tmp_path))
    assert out.patch is None
    assert any("skipped" in n for n in out.notes)
    # File untouched.
    assert (tmp_path / "auth.py").read_text(encoding="utf-8") == SOURCE_BEFORE
