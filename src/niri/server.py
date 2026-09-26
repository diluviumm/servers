"""Hermes Niri MCP server.

Introspection + safe window-manager actions untuk compositor Niri
(hanya `niri msg` JSON IPC — tanpa spawn, tanpa quit/power-off).

Run standalone:  python3 server.py   (MCP over stdio)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hermes-niri")


def _session_env() -> dict:
    """mcp SDK memangkas env child ke whitelist — auto-discover socket Wayland/Niri."""
    import glob
    import re
    uid = os.getuid()
    env = dict(os.environ)
    runtime = env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{uid}")
    if not env.get("WAYLAND_DISPLAY") or not os.path.exists(f"{runtime}/{env['WAYLAND_DISPLAY']}"):
        try:
            names = [p for p in os.listdir(runtime) if re.fullmatch(r"wayland-\d+", p)]
        except OSError:
            names = []
        if names:
            env["WAYLAND_DISPLAY"] = max(names)
    if not env.get("NIRI_SOCKET") or not os.path.exists(env.get("NIRI_SOCKET", "")):
        socks = sorted(glob.glob(f"{runtime}/niri.*.sock"), key=os.path.getmtime)
        if socks:
            env["NIRI_SOCKET"] = socks[-1]
    return env


def _run(cmd: list[str], timeout: int = 10) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=_session_env(), check=False)
    except Exception as exc:  # noqa: BLE001 - probe never crashes
        return {"code": -1, "out": "", "err": str(exc)}
    return {"code": r.returncode, "out": (r.stdout or "").strip(), "err": (r.stderr or "").strip()}


def _ensure_bin() -> str | None:
    return shutil.which("niri")


def _json_msgs(args: list[str]) -> object | None:
    res = _run(["niri", "msg", "--json"] + args)
    if res["code"] != 0:
        return None
    try:
        return json.loads(res["out"] or "null")
    except json.JSONDecodeError:
        return None


def _action(args: list[str]) -> dict:
    if not _ensure_bin():
        return {"ok": False, "error": "niri not installed"}
    res = _run(["niri", "msg", "action"] + args)
    if res["code"] != 0:
        return {"ok": False, "code": res["code"], "error": res["err"] or res["out"] or "action failed"}
    return {"ok": True, "action": args[0] if args else None}


@mcp.tool()
def overview() -> dict:
    """Peta desktop Niri: outputs, workspaces (aktif/fokus), jendela terbuka
    (id, app, judul, workspace) — dasar sebelum memanggil action lain."""
    if not _ensure_bin():
        return {"error": "niri not installed"}

    outputs_res = _run(["niri", "msg", "--json", "outputs"])
    if outputs_res["code"] != 0:
        return {"ok": False, "error": "niri msg gagal (sesi Wayland?)",
                "detail": outputs_res["err"] or outputs_res["out"]}
    outputs_raw = json.loads(outputs_res["out"] or "[]")
    if isinstance(outputs_raw, dict):   # {"HDMI-A-1": {...}} — dict keyed by name
        outputs_raw = list(outputs_raw.values())
    workspaces_raw = _json_msgs(["workspaces"]) or []
    windows_raw = _json_msgs(["windows"]) or []
    focused_raw = _json_msgs(["focused-window"])

    outputs = []
    for o in (outputs_raw if isinstance(outputs_raw, list) else []):
        preferred = next(
            (f"{m.get('width')}x{m.get('height')}"
             for m in o.get("modes", []) if m.get("is_preferred")), None)
        outputs.append({
            "name": o.get("name"),
            "make": o.get("make"),
            "model": o.get("model"),
            "preferred_mode": preferred,
            "scale": o.get("scale"),
            "is_focused": o.get("is_focused"),
        })
    workspaces = [
        {
            "id": w.get("id"),
            "idx": w.get("idx"),
            "name": w.get("name"),
            "output": w.get("output"),
            "is_active": w.get("is_active"),
            "is_focused": w.get("is_focused"),
        }
        for w in (workspaces_raw if isinstance(workspaces_raw, list) else [])
    ]
    # map workspace id -> idx utk windows
    ws_ref = {w.get("id"): (w.get("name") or w.get("idx")) for w in workspaces_raw} if isinstance(workspaces_raw, list) else {}
    windows = [
        {
            "id": wd.get("id"),
            "app_id": wd.get("app_id"),
            "title": (wd.get("title") or "")[:120],
            "workspace": ws_ref.get(wd.get("workspace_id")),
            "is_focused": wd.get("is_focused"),
        }
        for wd in (windows_raw if isinstance(windows_raw, list) else [])
    ]
    focused = None
    if isinstance(focused_raw, dict):
        focused = {"id": focused_raw.get("id"), "title": (focused_raw.get("title") or "")[:120],
                   "app_id": focused_raw.get("app_id")}
    return {"outputs": outputs, "workspaces": workspaces, "windows": windows,
            "focused": focused, "counts": {"outputs": len(outputs),
                                           "workspaces": len(workspaces), "windows": len(windows)}}


@mcp.tool()
def focus_workspace(reference: str) -> dict:
    """Fokus ke workspace berdasarkan index atau nama (lihat overview dulu)."""
    ref = str(reference).strip()
    if not ref:
        return {"ok": False, "error": "reference kosong"}
    return _action(["focus-workspace", ref])


@mcp.tool()
def focus_window(window_id: int) -> dict:
    """Fokus ke jendela spesifik berdasarkan id (lihat overview dulu)."""
    return _action(["focus-window", "--id", str(int(window_id))])


@mcp.tool()
def move_window_to_workspace(reference: str) -> dict:
    """Pindahkan jendela yang sedang FOKUS ke workspace lain (index/nama).
    Pindahkan fokus dulu (focus_window) bila tujuannya bukan jendela fokus."""
    ref = str(reference).strip()
    if not ref:
        return {"ok": False, "error": "reference kosong"}
    return _action(["move-window-to-workspace", ref])


@mcp.tool()
def close_window(window_id: int) -> dict:
    """Tutup jendela spesifik berdasarkan id (close-window --id, tanpa perlu fokus)."""
    return _action(["close-window", "--id", str(int(window_id))])


if __name__ == "__main__":
    mcp.run()
