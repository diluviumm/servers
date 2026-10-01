"""Hermes Portal MCP server.

Gerbang output desktop: screenshot layar (via Niri `screenshot-screen
--write-to-disk`) + clipboard read/write (wl-clipboard). Tanpa dialog,
tanpa instalasi tambahan (niri + wl-clipboard sudah ada di mesin).

Run standalone:  python3 server.py   (MCP over stdio)
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("hermes-portal")

DEFAULT_SHOT_DIR = os.path.expanduser("~/Pictures/Screenshots")


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


def _run(cmd: list[str], timeout: int = 15, stdin: str | None = None) -> dict:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            input=stdin, env=_session_env(), check=False,
        )
    except Exception as exc:  # noqa: BLE001 - probe never crashes
        return {"code": -1, "out": "", "err": str(exc)}
    return {"code": r.returncode, "out": r.stdout or "", "err": (r.stderr or "").strip()}


def _shot_dir() -> str:
    """Folder tujuan screenshot niri (dari konfigurasi screenshot-path user)."""
    try:
        with open(os.path.expanduser("~/.config/niri/config.kdl"), encoding="utf-8") as fh:
            m = re.search(r'screenshot-path\s+"([^"]+)"', fh.read())
        if m:
            return os.path.dirname(os.path.expanduser(m.group(1))) or DEFAULT_SHOT_DIR
    except OSError:
        pass
    return DEFAULT_SHOT_DIR


def _snap_dir(d: str) -> dict:
    snap = {}
    for name in os.listdir(d):
        p = os.path.join(d, name)
        try:
            if os.path.isfile(p):
                snap[name] = (os.path.getmtime(p), os.path.getsize(p))
        except OSError:
            continue
    return snap


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
def screenshot(save_to: str = "") -> dict:
    """Ambil screenshot layar fokus ke file PNG. Niri menulis ke folder
    screenshot-path lalu file dipindahkan ke `save_to` bila diminta
    (default: file tetap di folder screenshot niri). Screenshot juga
    masuk clipboard sistem sebagai efek samping native Niri."""
    if not shutil.which("niri"):
        return {"ok": False, "error": "niri not installed"}

    shot_dir = _shot_dir()
    os.makedirs(shot_dir, exist_ok=True)
    before = _snap_dir(shot_dir)

    res = _run(["niri", "msg", "action", "screenshot-screen", "--write-to-disk", "true"])
    if res["code"] != 0:
        return {"ok": False, "code": res["code"], "error": res["err"] or res["out"] or "screenshot failed"}

    # niri menulis file sedikit setelah command kembali — poll file baru/berubah
    found = None
    for _ in range(30):
        for name, meta in _snap_dir(shot_dir).items():
            if name not in before or before[name] != meta:
                found = os.path.join(shot_dir, name)
                break
        if found:
            break
        time.sleep(0.15)
    if not found:
        return {"ok": False, "error": f"file baru tak muncul di {shot_dir}"}

    target = found
    if save_to:
        target = os.path.abspath(os.path.expanduser(save_to))
        parent = os.path.dirname(target)
        if parent:
            os.makedirs(parent, exist_ok=True)
        if os.path.abspath(target) != os.path.abspath(found):
            try:
                shutil.move(found, target)
            except OSError as exc:
                return {"ok": False, "error": f"gagal memindahkan file: {exc}",
                        "source": found}
    try:
        size = os.path.getsize(target)
    except OSError as exc:
        return {"ok": False, "error": f"file hasil screenshot tak terbaca: {exc}"}
    return {"ok": True, "path": target, "size_bytes": size,
            "clipboard_side_effect": "screenshot mengisi clipboard sistem"}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
def clipboard_read() -> dict:
    """Baca isi teks clipboard sistem (wl-paste). Kosong bila clipboard tak berisi teks."""
    if not shutil.which("wl-paste"):
        return {"ok": False, "error": "wl-paste not installed"}
    res = _run(["wl-paste", "--no-newline", "--type", "text"], timeout=8)
    if res["code"] != 0:
        err = res["err"]
        if "Wayland" in err or "XDG_RUNTIME" in err or res["code"] == -1:
            return {"ok": False, "error": f"wl-paste gagal: {err}"}
        # exit 1 = clipboard kosong / bukan teks (gambar dsb.)
        return {"ok": True, "empty": True, "text": "", "note": err or "no text clipboard"}
    return {"ok": True, "empty": not res["out"], "text": res["out"]}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False))
def clipboard_write(text: str) -> dict:
    """Tulis teks ke clipboard sistem (wl-copy) — menimpa isi clipboard."""
    if not shutil.which("wl-copy"):
        return {"ok": False, "error": "wl-copy not installed"}
    res = _run(["wl-copy"], timeout=8, stdin=text)
    if res["code"] != 0:
        return {"ok": False, "code": res["code"], "error": res["err"] or "wl-copy failed"}
    return {"ok": True, "chars": len(text)}


if __name__ == "__main__":
    mcp.run()
