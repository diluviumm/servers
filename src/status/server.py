"""Hermes Status MCP server.

Health checks for a self-hosted Hermes Agent stack: gateway, Cloudflare
tunnel, local portal, systemd units, ports, disk, memory, trivy DB age —
plus a pattern-grouped error summary for zero-touch debugging.

Run standalone:  python3 server.py   (MCP over stdio)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import urllib.request
from collections import Counter

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hermes-status")

# Ports that define this deployment; checked for listening state.
KNOWN_PORTS = [9080, 8888, 20128, 7456]

ERRORS_LOG = "/home/mael/.hermes/logs/errors.log"
GATEWAY_HEARTBEAT = "/home/mael/.hermes/state/gateway.heartbeat"
TRIVY_DB_META = os.path.expanduser("~/.cache/trivy/db/metadata.json")


def _user_env() -> dict:
    """systemctl --user needs a session bus; MCP child env may lack both."""
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
            check=False,
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


def _disk_usage() -> dict:
    out = _run(["df", "-P", "/"], timeout=8)
    for ln in out.splitlines()[1:]:
        parts = ln.split()
        if len(parts) >= 5 and parts[-1] == "/":
            try:
                used = int(parts[4].rstrip("%"))
            except ValueError:
                continue
            return {"root_used_pct": used, "root_free": parts[3],
                    "warn": used >= 90}
    return {"root_used_pct": None}


def _memory() -> dict:
    info = {}
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                info[key] = rest.split()[0]  # kB
    except OSError:
        return {"error": "meminfo unreadable"}
    total = int(info.get("MemTotal", 0))
    avail = int(info.get("MemAvailable", 0))
    return {
        "total_mb": total // 1024,
        "available_mb": avail // 1024,
        "used_pct": round((total - avail) * 100 / total, 1) if total else None,
        "swap_total_mb": int(info.get("SwapTotal", 0)) // 1024,
    }


def _load() -> dict:
    try:
        with open("/proc/loadavg", encoding="utf-8") as fh:
            one, five, fifteen = fh.read().split()[:3]
        return {"1m": float(one), "5m": float(five), "15m": float(fifteen)}
    except (OSError, ValueError):
        return {"error": "loadavg unreadable"}


def _gateway_uptime_s() -> int | None:
    """Age of the oldest hermes-gateway process (seconds)."""
    pids = [p for p in _run(["pgrep", "-f", "hermes.*gateway"]).split() if p.isdigit()]
    if not pids:
        return None
    out = _run(["ps", "-o", "etimes=", "-p", ",".join(pids)], timeout=8)
    ages = [int(x) for x in out.split() if x.strip().isdigit()]
    return max(ages) if ages else None


def _trivy_db_age_h() -> float | None:
    try:
        with open(TRIVY_DB_META, encoding="utf-8") as fh:
            meta = json.load(fh)
        updated = meta.get("UpdatedAt") or ""
        ts = time.mktime(time.strptime(updated[:19], "%Y-%m-%dT%H:%M:%S"))
        return round((time.time() - ts) / 3600, 1)
    except Exception:  # noqa: BLE001 - absent/odd metadata just means unknown
        return None


_TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[\d:.+-]*Z?")
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                   re.IGNORECASE)
_HEX = re.compile(r"\b0x[0-9a-fA-F]{6,}\b")
_NUM = re.compile(r"\b\d+\b")


def normalize_error_line(line: str) -> str:
    """Strip volatile parts so repeated errors collapse into one pattern."""
    line = _TS.sub("<TS>", line)
    line = _UUID.sub("<UUID>", line)
    line = _HEX.sub("<HEX>", line)
    line = _NUM.sub("<N>", line)
    return " ".join(line.split())[:160]


@mcp.tool()
def health() -> dict:
    """Kesehatan infra lengkap: gateway, tunnel, portal, unit gagal, port, disk, RAM, load, trivy DB."""
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

    hb_age = None
    if os.path.exists(GATEWAY_HEARTBEAT):
        hb_age = int(time.time() - os.path.getmtime(GATEWAY_HEARTBEAT))

    listening = set()
    for ln in _run(["ss", "-ltnH"]).splitlines():
        parts = ln.split()
        if len(parts) >= 4 and ":" in parts[3]:
            try:
                listening.add(int(parts[3].rsplit(":", 1)[1]))
            except ValueError:
                continue

    tunnel_alive = bool(tunnel_pids.split()) and tunnel_pids.split()[0].isdigit()
    disk = _disk_usage()
    db_age = _trivy_db_age_h()
    portal = _http_ok("http://127.0.0.1:9080/api/notice")

    return {
        "gateway": {
            "active": gateway_active == "active",
            "detail": gateway_active,
            "pids": int(gateway_pids) if str(gateway_pids).isdigit() else 0,
            "uptime_s": _gateway_uptime_s(),
            "heartbeat_age_s": hb_age,
        },
        "tunnel": {
            "process_running": tunnel_alive,
            "pids": [p for p in tunnel_pids.split() if p.isdigit()],
        },
        "portal": portal,
        "hindsight": _http_ok(
            "http://127.0.0.1:8888/v1/default/banks/hermes/memories/list?limit=1"
        ),
        "failed_systemd_units": failed_units,
        "known_ports_listening": {str(p): p in listening for p in KNOWN_PORTS},
        "disk": disk,
        "memory": _memory(),
        "load": _load(),
        "trivy_db_age_h": db_age,
        "trivy_db_stale": (db_age is None or db_age >= 48),
        "ok": (
            gateway_active == "active"
            and not failed_units
            and portal.get("ok")
            and not disk.get("warn", False)
        ),
    }


@mcp.tool()
def recent_errors(n: int = 60) -> dict:
    """Tail errors.log lalu kelompokkan menjadi pola error unik + frekuensi (debugging zero-touch)."""
    try:
        with open(ERRORS_LOG, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        return {"error": "errors.log not found", "patterns": [], "tail": []}

    window = lines[-max(1, min(n, 500)):]
    counter: Counter[str] = Counter(normalize_error_line(ln) for ln in window)
    top = [
        {"count": count, "pattern": pattern}
        for pattern, count in counter.most_common(10)
    ]
    return {
        "window_lines": len(window),
        "file_lines": len(lines),
        "unique_patterns": len(counter),
        "top_patterns": top,
        "tail": [ln.rstrip() for ln in window[-15:]],
    }


if __name__ == "__main__":
    mcp.run()
