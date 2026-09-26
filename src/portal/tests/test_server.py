"""Tests for the hermes-portal MCP server (niri/wl-clipboard mocked)."""

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "portal_server", Path(__file__).resolve().parents[1] / "server.py"
)
assert _spec is not None and _spec.loader is not None
server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(server)


def test_screenshot_moves_new_file_to_save_to(tmp_path, monkeypatch):
    shot_dir = tmp_path / "shots"
    shot_dir.mkdir()
    monkeypatch.setattr(server, "_shot_dir", lambda: str(shot_dir))
    monkeypatch.setattr(server.shutil, "which", lambda n: f"/usr/bin/{n}")
    target = tmp_path / "out" / "shot.png"

    def fake_run(cmd, timeout=15, stdin=None):
        assert cmd[-2:] == ["--write-to-disk", "true"]  # boolean, bukan path
        (shot_dir / "niri-shot.png").write_bytes(b"\x89PNG-fake")
        return {"code": 0, "out": "", "err": ""}

    monkeypatch.setattr(server, "_run", fake_run)
    out = server.screenshot(save_to=str(target))
    assert out["ok"] is True and out["path"] == str(target)
    assert Path(out["path"]).exists() and out["size_bytes"] > 0
    assert not (shot_dir / "niri-shot.png").exists()  # pindah, bukan copy


def test_screenshot_default_keeps_file_in_shot_dir(tmp_path, monkeypatch):
    shot_dir = tmp_path / "shots"
    shot_dir.mkdir()
    monkeypatch.setattr(server, "_shot_dir", lambda: str(shot_dir))
    monkeypatch.setattr(server.shutil, "which", lambda n: f"/usr/bin/{n}")

    def fake_run(cmd, timeout=15, stdin=None):
        (shot_dir / "screenshot from 2026-09-26.png").write_bytes(b"\x89PNG-fake")
        return {"code": 0, "out": "", "err": ""}

    monkeypatch.setattr(server, "_run", fake_run)
    out = server.screenshot()
    assert out["ok"] is True and out["path"].startswith(str(shot_dir))
    assert Path(out["path"]).exists()


def test_screenshot_missing_binary(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda n: None)
    assert server.screenshot(save_to="/tmp/x.png")["ok"] is False


def test_screenshot_action_failure(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(
        server, "_run",
        lambda cmd, timeout=15, stdin=None: {"code": 1, "out": "", "err": "no compositor"},
    )
    out = server.screenshot(save_to="/tmp/x.png")
    assert out["ok"] is False and "no compositor" in out["error"]


def test_clipboard_roundtrip(monkeypatch):
    seen = {}
    monkeypatch.setattr(server.shutil, "which", lambda n: f"/usr/bin/{n}")

    def fake_run(cmd, timeout=15, stdin=None):
        if cmd[0] == "wl-paste":
            return {"code": 0, "out": "hello world", "err": ""}
        seen["copy"] = stdin
        return {"code": 0, "out": "", "err": ""}

    monkeypatch.setattr(server, "_run", fake_run)
    assert server.clipboard_read() == {"ok": True, "empty": False, "text": "hello world"}
    out = server.clipboard_write("hasil agent")
    assert out["ok"] is True and seen["copy"] == "hasil agent"


def test_clipboard_empty_and_failure(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(
        server, "_run",
        lambda cmd, timeout=15, stdin=None: {"code": 1, "out": "", "err": "No selection"},
    )
    empty = server.clipboard_read()
    assert empty["ok"] is True and empty["empty"] is True


def test_screenshot_move_failure_reported(tmp_path, monkeypatch):
    shot_dir = tmp_path / "shots"
    shot_dir.mkdir()
    monkeypatch.setattr(server, "_shot_dir", lambda: str(shot_dir))
    monkeypatch.setattr(server.shutil, "which", lambda n: f"/usr/bin/{n}")

    def fake_run(cmd, timeout=15, stdin=None):
        (shot_dir / "s.png").write_bytes(b"\x89PNG")
        return {"code": 0, "out": "", "err": ""}

    monkeypatch.setattr(server, "_run", fake_run)

    def boom(src, dst):
        raise OSError("cross-device denied")

    monkeypatch.setattr(server.shutil, "move", boom)
    out = server.screenshot(save_to=str(tmp_path / "out.png"))
    assert out["ok"] is False and "gagal memindahkan" in out["error"]

def test_session_env_discovers_sockets(tmp_path, monkeypatch):
    """mcp SDK memangkas env child — auto-discover Wayland & Niri socket."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.delenv("NIRI_SOCKET", raising=False)
    (tmp_path / "wayland-1").touch()
    (tmp_path / "niri.wayland-1.99.sock").touch()
    env = server._session_env()
    assert env["WAYLAND_DISPLAY"] == "wayland-1"
    assert env["NIRI_SOCKET"] == str(tmp_path / "niri.wayland-1.99.sock")


def test_session_env_keeps_valid_existing(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    (tmp_path / "wayland-7").touch()
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-7")
    env = server._session_env()
    assert env["WAYLAND_DISPLAY"] == "wayland-7"

