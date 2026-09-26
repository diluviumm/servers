"""Tests for the hermes-status MCP server (no live infra required)."""

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "status_server", Path(__file__).resolve().parents[1] / "server.py"
)
assert _spec is not None and _spec.loader is not None
server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(server)


def test_normalize_collapses_volatile_parts():
    a = server.normalize_error_line(
        "2026-09-26T09:00:00+08:00 ERROR gateway pid 46344 crashed at 0x7fff12345678 code 1"
    )
    b = server.normalize_error_line(
        "2026-09-26T10:11:12+08:00 ERROR gateway pid 99999 crashed at 0xabcdef990000 code 2"
    )
    assert a == b
    assert "<TS>" in a and "<N>" in a


def test_normalize_strips_uuid():
    a = server.normalize_error_line("session 550e8400-e29b-41d4-a716-446655440000 timed out")
    b = server.normalize_error_line("session 123e4567-e89b-42d3-a456-426614174000 timed out")
    assert a == b


def test_health_shape(monkeypatch):
    def fake_run(cmd, timeout=15, user=False):
        if cmd[:2] == ["systemctl", "--user"]:
            return "active" if "is-active" in cmd else ""
        if cmd[0] == "pgrep":
            return "46344"
        if cmd[0] == "ss":
            return "LISTEN 0 4096 127.0.0.1:9080 0.0.0.0:*"
        if cmd[0] == "ps":
            return "12345"
        if cmd[0] == "df":
            return ("Filesystem 1024-blocks Used Available Capacity Mounted\n"
                    "/dev/sda1 100 50 50 50% /")
        return ""

    monkeypatch.setattr(server, "_run", fake_run)
    monkeypatch.setattr(server, "_http_ok", lambda url, timeout=4: {"ok": True, "status": 200})

    h = server.health()
    for key in ("gateway", "tunnel", "portal", "hindsight", "failed_systemd_units",
                "known_ports_listening", "disk", "memory", "load", "trivy_db_age_h",
                "trivy_db_stale", "ok"):
        assert key in h, f"missing key: {key}"
    assert h["gateway"]["active"] is True
    assert h["gateway"]["uptime_s"] == 12345
    assert h["disk"]["root_used_pct"] == 50
    assert isinstance(h["ok"], bool)


def test_recent_errors_groups_patterns(tmp_path, monkeypatch):
    log = tmp_path / "errors.log"
    log.write_text(
        "2026-09-26T09:00:01 ERROR gateway pid 1 failed\n"
        "2026-09-26T09:00:02 ERROR gateway pid 2 failed\n"
        "2026-09-26T09:00:03 WARN ok something else\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(server, "ERRORS_LOG", str(log))
    result = server.recent_errors(10)
    assert result["window_lines"] == 3
    assert result["unique_patterns"] == 2
    top = result["top_patterns"][0]
    assert top["count"] == 2
    assert "ERROR gateway pid" in top["pattern"]


def test_recent_errors_missing_log(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "ERRORS_LOG", str(tmp_path / "nope.log"))
    assert server.recent_errors()["error"] == "errors.log not found"
