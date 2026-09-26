"""Tests for the hermes-owasp MCP server (scanners mocked, no network)."""

import importlib.util
import json
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "owasp_server", Path(__file__).resolve().parents[1] / "server.py"
)
assert _spec is not None and _spec.loader is not None
server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(server)


def test_nuclei_rejects_foreign_host():
    with pytest.raises(ValueError, match="allow-list"):
        server.nuclei_scan("https://evil.example.com")


def test_nuclei_accepts_allow_listed_host(monkeypatch):
    monkeypatch.setattr(server, "_run", lambda cmd, timeout: {"code": 0, "out": "", "err": ""})
    out = server.nuclei_scan("http://127.0.0.1:9080")
    assert out["count"] == 0
    assert out["exit"] == 0


def test_nuclei_templates_flag_included(monkeypatch):
    captured = {}

    def fake_run(cmd, timeout):
        captured["cmd"] = cmd
        return {"code": 0, "out": "", "err": ""}

    monkeypatch.setattr(server, "_run", fake_run)
    server.nuclei_scan("127.0.0.1:9080")
    assert "-t" in captured["cmd"]
    assert str(server.CUSTOM_TEMPLATES) in captured["cmd"]


def test_gitleaks_validates_mode_and_format():
    with pytest.raises(ValueError):
        server.gitleaks_scan("/tmp", mode="worktree")
    with pytest.raises(ValueError):
        server.gitleaks_scan("/tmp", format="xml")


def test_trivy_validates_format():
    with pytest.raises(ValueError):
        server.trivy_fs("/tmp", format="csv")


def test_brief_counts_and_limits():
    findings = [{"RuleID": f"r{i}", "Severity": "high"} for i in range(15)]
    brief = server._brief(findings, limit=5)
    assert brief["count"] == 15
    assert len(brief["sample"]) == 5


def test_sarif_and_junit_counters():
    sarif = json.dumps({"runs": [{"results": [{}, {}]}, {"results": [{}]}]})
    assert server._count_sarif(sarif) == 3
    junit = '<testsuite tests="5" failures="2">'
    assert server._count_junit(junit) == 2
    assert server._count_sarif("not json") is None


def test_write_md_and_table(tmp_path):
    target = tmp_path / "sub" / "report.md"
    out = server._write_md(str(target), "Title", [("Result", "3 findings"),
                                                  ("Detail", server._md_table(
                                                      [{"a": 1, "b": 2}], ["a", "b"]))])
    assert Path(out).exists()
    text = Path(out).read_text(encoding="utf-8")
    assert "# Title" in text and "| a | b |" in text
    assert server._md_table([], ["a"]) == "_no findings_"
