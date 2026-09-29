"""Tests for the hermes-status MCP server (no live infra required)."""

import importlib.util
import json
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


def test_registered_tool_count():
    """Regression: all six advertised tools must be registered (4 were lost in a rewrite)."""
    names = sorted(t.name for t in server.mcp._tool_manager.list_tools())
    assert names == ["config_view", "gateway_logs", "health", "ports",
                     "recent_errors", "services"]


def test_redact_masks_secrets():
    data = {"api_key": "abc123",
            "nested": {"oauth_token": "zzz", "model": "mimo-v2.6-flash"},
            "mcp_servers": {"cmd": "npx -y pkg"},
            "long": "A" * 48}
    out = server._redact(data)
    assert out["api_key"] == "[REDACTED]"
    assert out["nested"]["oauth_token"] == "[REDACTED]"
    assert out["nested"]["model"] == "mimo-v2.6-flash"
    assert out["mcp_servers"]["cmd"] == "npx -y pkg"
    assert out["long"] == "[REDACTED]"


def test_config_view_redacts_and_lists_sections(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("model: mimo-v2.6-flash\n"
                   "providers:\n  ocg:\n    api_key: dummyvalue1234567890abcdef\n",
                   encoding="utf-8")
    monkeypatch.setattr(server, "CONFIG_PATH", str(cfg))
    full = server.config_view()
    assert full["sections"] == ["model", "providers"]
    text = json.dumps(full["config"])
    assert "dummyvalue" not in text and "mimo-v2.6-flash" in text
    sec = server.config_view(section="model")
    assert sec["config"] == {"model": "mimo-v2.6-flash"}
    miss = server.config_view(section="nope")
    assert "not found" in miss["error"] and "model" in miss["sections"]


def test_ports_and_services_shapes(monkeypatch):
    def fake_run(cmd, timeout=15, user=False):
        if cmd[0] == "ss":
            return ('LISTEN 0 4096 127.0.0.1:9080 0.0.0.0:* users:'
                    '(("portal",pid=1,fd=3))')
        if "list-units" in cmd and "--state=failed" not in cmd:
            return "hermes-gateway.service loaded active running Hermes Gateway"
        if cmd[:2] == ["systemctl", "--user"] and "TriggeredBy" in cmd:
            return ""  # no timer -> not by design
        return ""

    monkeypatch.setattr(server, "_run", fake_run)
    monkeypatch.setattr(server, "_http_ok", lambda url, timeout=4: {"ok": True, "status": 200})
    p = server.ports()
    assert 9080 in p["listening_ports"]
    hit = server.ports(port=9080)
    assert hit["listening"] and '"portal"' in hit["entries"][0]["process"]
    s = server.services()
    assert s["units"][0]["unit"] == "hermes-gateway.service" and s["ok"]


def test_services_event_driven_unit_is_not_unhealthy(monkeypatch, tmp_path):
    """An OnFailure= watchdog resting at 'inactive' must not be flagged unhealthy.

    Regression: portal-alert (pure OnFailure target, no timer) was reported
    unhealthy for days because only timers counted as 'by design'.
    """
    (tmp_path / "hermes-portal-selftest.service").write_text(
        "[Unit]\nOnFailure=hermes-portal-alert.service\n")

    def fake_run(cmd, timeout=15, user=False):
        if cmd[0] == "systemctl" and "list-units" in cmd and "--state=failed" not in cmd:
            return ("hermes-portal-alert.service loaded inactive dead portal alert")
        return ""

    monkeypatch.setattr(server, "_run", fake_run)
    monkeypatch.setattr(
        server.os.path, "expanduser", lambda p: str(tmp_path) if "systemd" in p else p)
    monkeypatch.setattr(server, "_http_ok", lambda url, timeout=4: {"ok": True, "status": 200})
    s = server.services()
    assert s["unhealthy"] == []
    assert s["inactive_timer_driven"] == ["hermes-portal-alert.service"]
    assert s["ok"]


def test_services_unknown_inactive_unit_still_unhealthy(monkeypatch, tmp_path):
    """A unit inactive with no timer and no OnFailure/OnSuccess parent IS a problem."""
    (tmp_path / "unrelated.service").write_text("[Unit]\nDescription=nothing\n")

    def fake_run(cmd, timeout=15, user=False):
        if cmd[0] == "systemctl" and "list-units" in cmd and "--state=failed" not in cmd:
            return "hermes-orphan.service loaded inactive dead orphan"
        return ""

    monkeypatch.setattr(server, "_run", fake_run)
    monkeypatch.setattr(
        server.os.path, "expanduser", lambda p: str(tmp_path) if "systemd" in p else p)
    monkeypatch.setattr(server, "_http_ok", lambda url, timeout=4: {"ok": True, "status": 200})
    s = server.services()
    assert s["unhealthy"] == ["hermes-orphan.service"]
    assert not s["ok"]


def test_gateway_logs_redacts_tokens(monkeypatch):
    monkeypatch.setattr(
        server, "_run",
        lambda cmd, timeout=15, user=False: (
            "line with token " + "A" * 50 if cmd and cmd[0] == "journalctl" else ""),
    )
    out = server.gateway_logs(n=50)
    assert out["requested"] == 50
    assert all("A" * 40 not in ln for ln in out["lines"])
