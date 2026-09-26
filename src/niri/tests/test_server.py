"""Tests for the hermes-niri MCP server (compositor mocked, no live session)."""

import importlib.util
import json
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "niri_server", Path(__file__).resolve().parents[1] / "server.py"
)
assert _spec is not None and _spec.loader is not None
server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(server)

OUTPUTS = [{"name": "eDP-1", "scale": 1.0,
            "modes": [{"width": 1920, "height": 1080, "is_preferred": True}]}]
WORKSPACES = [
    {"id": 2, "idx": 1, "name": None, "output": "eDP-1", "is_active": True, "is_focused": True},
    {"id": 4, "idx": 2, "name": "web", "output": "eDP-1", "is_active": False, "is_focused": False},
]
WINDOWS = [
    {"id": 37, "app_id": "foot", "title": "terminal", "workspace_id": 2},
    {"id": 41, "app_id": "firefox", "title": "docs", "workspace_id": 4},
]
FOCUSED = {"id": 37, "title": "terminal", "app_id": "foot"}


def _fake_run_factory(calls):
    def fake_run(cmd, timeout=10):
        calls.append(cmd)
        if "--json" in cmd:
            topic = cmd[cmd.index("--json") + 1]
            payload = {"outputs": OUTPUTS, "workspaces": WORKSPACES,
                       "windows": WINDOWS, "focused-window": FOCUSED}[topic]
            return {"code": 0, "out": json.dumps(payload), "err": ""}
        return {"code": 0, "out": "", "err": ""}

    return fake_run


def test_overview_shape(monkeypatch):
    calls = []
    monkeypatch.setattr(server.shutil, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(server, "_run", _fake_run_factory(calls))
    ov = server.overview()
    assert ov["counts"] == {"outputs": 1, "workspaces": 2, "windows": 2}
    assert ov["workspaces"][1]["name"] == "web"
    assert ov["windows"][0]["workspace"] == 1          # id 2 -> idx 1
    assert ov["windows"][1]["workspace"] == "web"      # id 4 -> name
    assert ov["focused"]["id"] == 37
    assert ov["outputs"][0]["preferred_mode"] == "1920x1080"


def test_focus_workspace_builds_command(monkeypatch):
    calls = []
    monkeypatch.setattr(server.shutil, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(server, "_run", _fake_run_factory(calls))
    out = server.focus_workspace("web")
    assert out["ok"] is True
    assert ["niri", "msg", "action", "focus-workspace", "web"] in calls


def test_focus_workspace_rejects_empty(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda n: f"/usr/bin/{n}")
    assert server.focus_workspace("  ")["ok"] is False


def test_focus_and_close_window_use_id(monkeypatch):
    calls = []
    monkeypatch.setattr(server.shutil, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(server, "_run", _fake_run_factory(calls))
    assert server.focus_window(37)["ok"] is True
    assert server.close_window(41)["ok"] is True
    assert ["niri", "msg", "action", "focus-window", "--id", "37"] in calls
    assert ["niri", "msg", "action", "close-window", "--id", "41"] in calls


def test_missing_binary_is_reported(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda n: None)
    assert "error" in server.overview()
    assert server.focus_window(1)["ok"] is False


def test_action_failure_surfaces_stderr(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda n: f"/usr/bin/{n}")

    def fail_run(cmd, timeout=10):
        return {"code": 2, "out": "", "err": "no such workspace"}

    monkeypatch.setattr(server, "_run", fail_run)
    out = server.focus_workspace("99")
    assert out["ok"] is False and "no such workspace" in out["error"]


def test_overview_invalid_json_is_reported(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda n: f"/usr/bin/{n}")

    def bad_run(cmd, timeout=10):
        if "--json" in cmd and cmd[cmd.index("--json") + 1] == "outputs":
            return {"code": 0, "out": "<html>proxy error", "err": ""}
        payload = {"workspaces": WORKSPACES, "windows": WINDOWS,
                   "focused-window": FOCUSED}[cmd[cmd.index("--json") + 1]]
        return {"code": 0, "out": json.dumps(payload), "err": ""}

    monkeypatch.setattr(server, "_run", bad_run)
    out = server.overview()
    assert out["ok"] is False and "JSON" in out["error"]


def test_overview_modes_null_safe(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda n: f"/usr/bin/{n}")
    outputs = [{"name": "eDP-1", "modes": None}]

    def run(cmd, timeout=10):
        if "--json" in cmd:
            topic = cmd[cmd.index("--json") + 1]
            payload = {"outputs": outputs, "workspaces": [], "windows": [],
                       "focused-window": None}[topic]
            return {"code": 0, "out": json.dumps(payload), "err": ""}
        return {"code": 0, "out": "", "err": ""}

    monkeypatch.setattr(server, "_run", run)
    ov = server.overview()
    assert ov["ok"] is True
    assert ov["outputs"][0]["preferred_mode"] is None
