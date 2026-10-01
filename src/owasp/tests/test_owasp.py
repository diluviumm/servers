"""Tests for the hermes-owasp MCP server (scanners mocked, no network)."""

import importlib.util
import json
import time
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
    monkeypatch.setattr(server, "_bin", lambda name: name)
    monkeypatch.setattr(server, "_run", lambda cmd, timeout: {"code": 0, "out": "", "err": ""})
    out = server.nuclei_scan("http://127.0.0.1:9080")
    assert out["count"] == 0
    assert out["exit"] == 0


def test_nuclei_templates_flag_included(monkeypatch):
    monkeypatch.setattr(server, "_bin", lambda name: name)
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


def test_gitleaks_json_with_output_file_reads_from_file(tmp_path, monkeypatch):
    """Regression: report written to output_file must be counted from the FILE,
    not from the (empty) stdout."""
    target = tmp_path / "report.json"
    monkeypatch.setattr(server, "_bin", lambda name: name)

    def fake_run(cmd, timeout):
        Path(cmd[cmd.index("--report-path") + 1]).write_text(
            json.dumps([{"RuleID": "a", "Secret": "s"},
                        {"RuleID": "b", "Secret": "s2"},
                        {"RuleID": "c", "Secret": "s3"}]),
            encoding="utf-8",
        )
        return {"code": 1, "out": "", "err": ""}

    monkeypatch.setattr(server, "_run", fake_run)
    out = server.gitleaks_scan("/tmp", format="json", output_file=str(target))
    assert out["count"] == 3
    assert out["clean"] is False
    assert out["report_file"] == str(target)


def test_bearer_with_output_file_reads_from_file(tmp_path, monkeypatch):
    """Regression: bearer --output writes JSON to file; stdout is empty."""
    target = tmp_path / "bearer.json"
    monkeypatch.setattr(server, "_bin", lambda name: name)

    def fake_run(cmd, timeout):
        Path(cmd[cmd.index("--output") + 1]).write_text(
            json.dumps({"critical": [{"id": "x", "filename": "f.py",
                                      "line_number": 3}]}),
            encoding="utf-8",
        )
        return {"code": 1, "out": "", "err": ""}

    monkeypatch.setattr(server, "_run", fake_run)
    out = server.bearer_scan("/tmp", output_file=str(target))
    assert out["total"] == 1
    assert out["by_severity"] == {"critical": 1}
    assert out["sample"][0]["file"] == "f.py"


def test_gitleaks_junit_reads_written_report(tmp_path, monkeypatch):
    """Regression: branch junit must read the EXACT path gitleaks wrote.

    Suffix mismatch (.gitleaks.junit vs .gitleaks.junit.xml) hid the report
    -> failures was never counted (always None).
    """
    monkeypatch.setattr(server, "_bin", lambda name: name)

    def fake_run(cmd, timeout):
        report = Path(cmd[cmd.index("--report-path") + 1])
        report.write_text('<testsuite tests="4" failures="3"></testsuite>',
                          encoding="utf-8")
        return {"code": 1, "out": "", "err": ""}

    monkeypatch.setattr(server, "_run", fake_run)
    out = server.gitleaks_scan(str(tmp_path), format="junit",
                               report_md=str(tmp_path / "r.md"))
    assert out["failures"] == 3


def test_count_junit_attribute_order_and_clean_zero():
    """gitleaks prints failures= BEFORE tests= — order-independent parse; clean scan == 0, non-junit == None."""
    xml = '<testsuite failures="0" name="gitleaks" tests="0" time=""></testsuite>'
    assert server._count_junit(xml) == 0
    assert server._count_junit('<testsuite tests="5" failures="2">') == 2
    assert server._count_junit("plain text, not a report") is None


def test_bearer_ignore_file_wiring(tmp_path, monkeypatch):
    """Baseline FP: bearer.ignore (state) dipass sebagai --ignore-file bila ada."""
    monkeypatch.setattr(server, "_bin", lambda n: n)
    ignore = tmp_path / "bearer.ignore"
    ignore.write_text("test rule id\n", encoding="utf-8")
    monkeypatch.setattr(server, "BEARER_IGNORE", ignore)
    seen: dict = {}

    def fake_run(cmd, timeout):
        seen["cmd"] = cmd
        return {"code": 0, "out": json.dumps({"critical": []}), "err": ""}

    monkeypatch.setattr(server, "_run", fake_run)
    server.bearer_scan(str(tmp_path))
    assert "--ignore-file" in seen["cmd"] and str(ignore) in seen["cmd"]

    # tanpa file baseline -> flag tidak ditambahkan
    monkeypatch.setattr(server, "BEARER_IGNORE", tmp_path / "missing.ignore")
    server.bearer_scan(str(tmp_path))
    assert "--ignore-file" not in seen["cmd"]


def test_trivy_fs_sarif_counts_findings(tmp_path, monkeypatch):
    """Jalur format != json: report ditulis ke file lalu findings dihitung."""
    monkeypatch.setattr(server, "_bin", lambda n: n)
    monkeypatch.setattr(server, "_ensure_trivy_db", lambda: {"age_h": 1.0})
    target = tmp_path / "t.sarif"

    def fake_run(cmd, timeout):
        Path(cmd[cmd.index("--output") + 1]).write_text(
            json.dumps({"runs": [{"results": [{"rule": {"id": "A"}},
                                              {"rule": {"id": "B"}}]}]}),
            encoding="utf-8")
        return {"code": 0, "out": "", "err": ""}

    monkeypatch.setattr(server, "_run", fake_run)
    out = server.trivy_fs(str(tmp_path), format="sarif", output_file=str(target))
    assert out["saved_to"] == str(target) and out["findings"] == 2


def test_trivy_image_json_severity_counts(monkeypatch):
    monkeypatch.setattr(server, "_bin", lambda n: n)
    monkeypatch.setattr(server, "_ensure_trivy_db", lambda: {"age_h": 1.0})

    def fake_run(cmd, timeout):
        return {"code": 0, "out": json.dumps(
            {"Results": [{"Vulnerabilities": [{"Severity": "HIGH"},
                                              {"Severity": "CRITICAL"}]}]}),
            "err": ""}

    monkeypatch.setattr(server, "_run", fake_run)
    out = server.trivy_image("alpine:3.19")
    assert out["severity_counts"] == {"HIGH": 1, "CRITICAL": 1}
    assert out["sample"]


def test_all_tools_have_annotations():
    """MCP best practice: annotations wajib; scanner = readOnly + openWorld."""
    import asyncio
    tools = asyncio.run(server.mcp.list_tools())
    assert tools and all(t.annotations is not None for t in tools)
    by_name = {t.name: t for t in tools}
    assert by_name["nuclei_scan"].annotations.readOnlyHint is True
    assert by_name["nuclei_scan"].annotations.openWorldHint is True
    assert by_name["gitleaks_scan"].annotations.readOnlyHint is True


def test_trivy_image_sarif_timeout_surfaces_error(monkeypatch):
    """BUG #3: sarif branch returned no 'error' key on timeout (-1) — inconsistent
    with the json branch which reports it."""
    monkeypatch.setattr(server, "_bin", lambda n: n)
    monkeypatch.setattr(server, "_ensure_trivy_db", lambda: {"age_h": 1.0})
    monkeypatch.setattr(
        server, "_run",
        lambda cmd, timeout: {"code": -1, "out": "", "err": "timeout after 600s"})
    out = server.trivy_image("alpine:3.19", format="sarif")
    assert out["error"] == "timeout after 600s" and out["exit"] == -1


def test_trivy_fs_rejects_bad_format(tmp_path):
    with pytest.raises(ValueError):
        server.trivy_fs(str(tmp_path), format="xml")


def test_trivy_fs_run_error_surfaces(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_bin", lambda n: n)
    monkeypatch.setattr(server, "_ensure_trivy_db", lambda: {"age_h": 2.0})
    monkeypatch.setattr(
        server, "_run",
        lambda cmd, timeout: {"code": -1, "out": "", "err": "trivy crashed"})
    out = server.trivy_fs(str(tmp_path))
    assert out["error"] == "trivy crashed" and out["db"]["age_h"] == 2.0


def test_trivy_fs_unparseable_json(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_bin", lambda n: n)
    monkeypatch.setattr(server, "_ensure_trivy_db", lambda: {"age_h": 2.0})
    monkeypatch.setattr(
        server, "_run",
        lambda cmd, timeout: {"code": 0, "out": "<html>proxy injected",
                              "err": ""})
    assert "error" in server.trivy_fs(str(tmp_path))


def test_trivy_fs_junit_failures(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_bin", lambda n: n)
    monkeypatch.setattr(server, "_ensure_trivy_db", lambda: {"age_h": 2.0})
    target = tmp_path / "t.xml"

    def fake_run(cmd, timeout):
        Path(cmd[cmd.index("--output") + 1]).write_text(
            '<testsuite tests="3" failures="1">', encoding="utf-8")
        return {"code": 1, "out": "", "err": ""}

    monkeypatch.setattr(server, "_run", fake_run)
    out = server.trivy_fs(str(tmp_path), format="junit", output_file=str(target))
    assert out["failures"] == 1 and out["saved_to"] == str(target)


def test_trivy_image_sarif_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_bin", lambda n: n)
    monkeypatch.setattr(server, "_ensure_trivy_db", lambda: {"age_h": 2.0})
    monkeypatch.setattr(server, "STATE_DIR", tmp_path)

    def fake_run(cmd, timeout):
        Path(cmd[cmd.index("--output") + 1]).write_text(
            json.dumps({"runs": [{"results": [{"rule": {"id": "CVE-1"}}]}]}),
            encoding="utf-8")
        return {"code": 0, "out": "", "err": ""}

    monkeypatch.setattr(server, "_run", fake_run)
    out = server.trivy_image("img:1", format="sarif")
    assert out["saved_to"].startswith(str(tmp_path)) and out["findings"] == 1


def test_trivy_db_age_and_fresh_ensure(tmp_path, monkeypatch):
    """DB segar (<48h) -> _ensure_trivy_db KANAN tanpa refresh (spy: _run dilarang)."""
    meta = tmp_path / "metadata.json"
    meta.write_text(json.dumps(
        {"UpdatedAt": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())}),
        encoding="utf-8")
    monkeypatch.setattr(server, "TRIVY_DB_META", meta)
    age = server._trivy_db_age_h()
    assert age is not None and 0 <= age < 1

    def no_run(*args, **kwargs):
        raise AssertionError("refresh tak boleh jalan utk DB segar")

    monkeypatch.setattr(server, "_run", no_run)
    out = server._ensure_trivy_db()
    assert out["refreshed"] is False and out["stale"] is False


def test_trivy_db_age_bad_meta_is_none(tmp_path, monkeypatch):
    meta = tmp_path / "metadata.json"
    meta.write_text("bukan json", encoding="utf-8")
    monkeypatch.setattr(server, "TRIVY_DB_META", meta)
    assert server._trivy_db_age_h() is None


def test_nuclei_rejects_missing_templates_dir():
    with pytest.raises(ValueError):
        server.nuclei_scan("http://127.0.0.1:1", templates="/definitely/missing")


def test_nuclei_parses_jsonl_findings(monkeypatch):
    monkeypatch.setattr(server, "_bin", lambda n: n)
    line = json.dumps({"template-id": "custom-csp",
                       "info": {"severity": "low", "name": "CSP missing"},
                       "matched-at": "http://127.0.0.1/"})
    monkeypatch.setattr(
        server, "_run",
        lambda cmd, timeout: {"code": 0, "out": line + "\nnoise-not-json\n",
                              "err": ""})
    out = server.nuclei_scan("http://127.0.0.1:1")
    assert out["count"] == 1
    assert out["findings"][0]["id"] == "custom-csp"


def test_trivy_fs_json_report_md(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_bin", lambda n: n)
    monkeypatch.setattr(server, "_ensure_trivy_db", lambda: {"age_h": 1.0})
    monkeypatch.setattr(
        server, "_run",
        lambda cmd, timeout: {"code": 0, "out": json.dumps(
            {"Results": [{"Vulnerabilities": [
                {"VulnerabilityID": "CVE-1", "PkgName": "a", "Severity": "HIGH"}]}]}),
            "err": ""})
    md = tmp_path / "r.md"
    out = server.trivy_fs(str(tmp_path), report_md=str(md))
    assert out["report_md"] == str(md) and md.exists()
