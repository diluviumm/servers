"""Hermes Status MCP server.

Health checks for a self-hosted Hermes Agent stack: gateway, Cloudflare
tunnel, local portal, systemd units and listening ports.

Run standalone:  python3 server.py   (MCP over stdio)
"""

from __future__ import annotations

import json
import subprocess
import urllib.request

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hermes-status")

# Ports that define this deployment; checked for listening state.
KNOWN_PORTS = [9080, 8888, 20128, 7456]


def _user_env() -> dict:
    """systemctl --user needs a session bus; MCP child env may lack both."""
    import os

    uid = os.getuid()
    env = dict(os.environ)
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{uid}")
    env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{uid}/bus")
    return env


def _run(cmd: list[str], timeout: int = 15, user: bool = False) -> str:
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_user_env() if user else None,
        )
        return (r.stdout or r.stderr or "").strip()
    except Exception as exc:  # noqa: BLE001 - health probe never crashes
        return f"error: {exc}"


def _http_ok(url: str, timeout: int = 4) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return {"ok": resp.status < 400, "status": resp.status}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:120]}


@mcp.tool()
def health() -> dict:
    """Kesehatan infra: gateway, tunnel, portal, systemd failed units, port."""
    gateway_active = _run(["systemctl", "--user", "is-active", "hermes-gateway"], user=True)
    gateway_pids = _run(["pgrep", "-fc", "hermes.*gateway"]) or "0"
    tunnel_pids = _run(["pgrep", "-f", "cloudflared"])

    failed = _run(
        ["systemctl", "--user", "list-units", "--type=service", "--state=failed",
         "--no-legend", "--no-pager"],
        user=True,
    )
    failed_units = [
        ln.split()[0]
        for ln in failed.splitlines()
        if ln.strip() and ln.split()[0].endswith((".service", ".timer"))
    ][:20]

    import os
    import time

    hb_path = "/home/mael/.hermes/state/gateway.heartbeat"
    hb_age = None
    if os.path.exists(hb_path):
        hb_age = int(time.time() - os.path.getmtime(hb_path))

    listening = set()
    for ln in _run(["ss", "-ltnH"]).splitlines():
        parts = ln.split()
        if len(parts) >= 4 and ":" in parts[3]:
            try:
                listening.add(int(parts[3].rsplit(":", 1)[1]))
            except ValueError:
                continue

    tunnel_alive = bool(tunnel_pids.split()) and tunnel_pids.split()[0].isdigit()

    return {
        "gateway": {
            "active": gateway_active == "active",
            "detail": gateway_active,
            "pids": int(gateway_pids) if str(gateway_pids).isdigit() else 0,
            "heartbeat_age_s": hb_age,
        },
        "tunnel": {
            "process_running": tunnel_alive,
            "pids": [p for p in tunnel_pids.split() if p.isdigit()],
        },
        "portal": _http_ok("http://127.0.0.1:9080/api/notice"),
        "hindsight": _http_ok("http://127.0.0.1:8888/v1/default/banks/hermes/memories/list?limit=1"),
        "failed_systemd_units": failed_units,
        "known_ports_listening": {str(p): p in listening for p in KNOWN_PORTS},
        "ok": (
            gateway_active == "active"
            and not failed_units
            and _http_ok("http://127.0.0.1:9080/api/notice").get("ok")
        ),
    }


@mcp.tool()
def recent_errors(n: int = 30) -> str:
    """Tail n baris terakhir dari Hermes errors.log (untuk debugging zero-touch)."""
    try:
        with open("/home/mael/.hermes/logs/errors.log", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        return "".join(lines[-max(1, min(n, 200)):])
    except FileNotFoundError:
        return "errors.log not found"


if __name__ == "__main__":
    mcp.run()
