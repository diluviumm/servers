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
from pathlib import Path

import yaml
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("hermes-status")

# Ports that define this deployment; checked for listening state.
KNOWN_PORTS = [9080, 8888, 20128, 7456]

ERRORS_LOG = "/home/mael/.hermes/logs/errors.log"
GATEWAY_HEARTBEAT = "/home/mael/.hermes/state/gateway.heartbeat"
TRIVY_DB_META = os.path.expanduser("~/.cache/trivy/db/metadata.json")
CONFIG_PATH = "/home/mael/.hermes/config.yaml"

# Keys whose values must never leave the server un-redacted.
_SECRET_KEY_HINTS = ("token", "key", "secret", "password", "pass",
                     "credential", "auth", "cookie", "bearer")
_SECRET_VALUE_RE = re.compile(r"\b(?:sk-|ghp_|gho_|xox[baprs]-|eyJ[A-Za-z0-9_-]{8,})\S{8,}")
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-]{40,}\b")


def _redact(obj):
    """Recursively mask credentials: secret-looking keys AND token-shaped values."""
    if isinstance(obj, dict):
        return {
            k: ("[REDACTED]"
                if any(h in str(k).lower() for h in _SECRET_KEY_HINTS)
                else _redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    if isinstance(obj, str):
        out = _SECRET_VALUE_RE.sub("[REDACTED]", obj)
        return _LONG_TOKEN_RE.sub("[REDACTED]", out)
    return obj


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


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
def health() -> dict:
    """Snapshot kesehatan infra Hermes dalam satu panggilan: gateway (aktif/pid/uptime/heartbeat), tunnel cloudflared, portal & Hindsight HTTP, unit systemd failed, port listening, disk (warn >=90%), RAM, load, umur trivy DB. Pakai sebagai LANGKAH PERTAMA troubleshooting atau cek rutin sebelum tugas panjang. Return dict dengan 'ok' sebagai ringkasan; read-only, aman dipanggil kapan saja."""
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


def _tail_lines(path: str | Path, keep: int) -> tuple[list[str], int]:
    """Baca ~keep baris terakhir tanpa memuat seluruh file (seek dari akhir).
    Mengembalikan (baris, total_bytes_file)."""
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        total = fh.tell()
        block = 64 * 1024
        data = b""
        pos = total
        while pos > 0 and data.count(b"\n") <= keep:
            step = min(block, pos)
            pos -= step
            fh.seek(pos)
            data = fh.read(step) + data
            if len(data) > 8 * 1024 * 1024:
                break
    lines = data.decode("utf-8", errors="replace").splitlines(keepends=True)
    if pos > 0 and lines:
        lines = lines[1:]  # baris pertama mungkin terpotong di tengah
    return lines, total


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
def recent_errors(n: int = 60) -> dict:
    """Baca tail errors.log (buffer maks 5000 baris), normalisasi bagian volatil (timestamp/UUID/hex/angka), kelompokkan menjadi pola unik + frekuensi beserta cuplikan mentah terakhir. Pakai saat error berulang dan ingin tahu akar polanya tanpa scroll log manual. 'n' = lebar jendela baris (1-500). Read-only; log tak terbaca dikembalikan sebagai field 'error', tool tidak pernah crash."""
    try:
        lines, total_bytes = _tail_lines(ERRORS_LOG, 5000)
    except FileNotFoundError:
        return {"error": "errors.log not found", "patterns": [], "tail": []}
    except OSError as exc:  # PermissionError dll — tool wajib tetap menjawab
        return {"error": f"errors.log tidak terbaca: {exc}", "patterns": [],
                "window_lines": 0, "file_bytes": 0, "buffered_lines": 0,
                "unique_patterns": 0, "top_patterns": [], "tail": []}

    window = lines[-max(1, min(n, 500)):]
    counter: Counter[str] = Counter(normalize_error_line(ln) for ln in window)
    top = [
        {"count": count, "pattern": pattern}
        for pattern, count in counter.most_common(10)
    ]
    return {
        "window_lines": len(window),
        "file_bytes": total_bytes,
        "buffered_lines": len(lines),
        "unique_patterns": len(counter),
        "top_patterns": top,
        "tail": [ln.rstrip() for ln in window[-15:]],
    }


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
def services(pattern: str = "hermes-*") -> dict:
    """Daftar unit systemd --user yang cocok glob 'pattern' (default 'hermes-*'), dipisah menjadi: sehat, inactive-karena-timer (by design), benar-benar unhealthy, plus daftar unit failed global. Pakai saat mencurigai service mati setelah reboot/update — membedakan 'mati karena timer' vs 'mati beneran'. Read-only; tidak pernah menjalankan atau menghentikan unit apa pun."""
    units = []
    raw = _run(
        ["systemctl", "--user", "list-units", "--all", "--no-legend",
         "--no-pager", "--type=service", pattern],
        user=True,
    )
    for ln in raw.splitlines():
        parts = ln.split(None, 4)
        if len(parts) >= 4 and parts[0].endswith(".service"):
            units.append({
                "unit": parts[0],
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": parts[4] if len(parts) > 4 else "",
            })

    failed_raw = _run(
        ["systemctl", "--user", "list-units", "--type=service", "--state=failed",
         "--no-legend", "--no-pager"],
        user=True,
    )
    failed = [
        ln.split()[0]
        for ln in failed_raw.splitlines()
        if ln.strip() and ln.split()[0].endswith(".service")
    ]

    def _timer_driven_active(unit_name: str) -> bool:
        """A service inactive between runs is by design when an ACTIVE timer drives it."""
        trig = _run(["systemctl", "--user", "show", unit_name,
                     "-p", "TriggeredBy", "--value"], user=True)
        for t in trig.split(","):
            t = t.strip()
            if t.endswith(".timer") and _run(
                    ["systemctl", "--user", "is-active", t], user=True).strip() == "active":
                return True
        return False

    def _event_driven_units() -> set:
        """Units referenced as OnFailure=/OnSuccess= targets by ANY user unit.

        Those only run on a failure/success event, so `active=inactive` is their
        resting state — flagging them as unhealthy is a false positive (the
        portal-alert watchdog spent days 'unhealthy' for exactly this reason).
        Unit files AND drop-ins (`foo.service.d/*.conf`) both count; one glob per
        dir replaces one `systemctl show` call per unit.
        """
        targets: set[str] = set()
        dirs = [os.path.expanduser("~/.config/systemd/user"),
                "/usr/lib/systemd/user", "/etc/systemd/user"]
        for d in dirs:
            # unit files + drop-ins (`foo.service.d/*.conf`) — both may declare the hooks
            files = list(Path(d).glob("*.service")) + list(Path(d).glob("*.service.d/*.conf"))
            for f in files:
                try:
                    lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
                except OSError:
                    continue
                targets.update(t for ln in lines if ln.startswith(("OnFailure=", "OnSuccess="))
                               for t in ln.split("=", 1)[1].split())
        return targets

    event_driven = _event_driven_units()
    by_design = sorted(
        u["unit"] for u in units
        if u["active"] != "active"
        and (u["unit"] in event_driven or _timer_driven_active(u["unit"]))
    )
    # Units not active, not timer-driven and not event-driven are the real problems.
    unhealthy = sorted(
        u["unit"] for u in units
        if u["active"] != "active" and u["unit"] not in by_design
    )
    tunnel = _run(["pgrep", "-f", "cloudflared"])
    return {
        "pattern": pattern,
        "units": units,
        "failed": failed,
        "inactive_timer_driven": by_design,
        "unhealthy": unhealthy,
        "tunnel_pids": [p for p in tunnel.split() if p.isdigit()],
        "portal": _http_ok("http://127.0.0.1:9080/api/notice"),
        "ok": bool(units) and not failed and not unhealthy,
    }


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
def ports(port: int | None = None) -> dict:
    """Daftar port listening dari 'ss -ltnpH' beserta proses pemiliknya; parameter 'port' opsional untuk mengecek satu port persis (mis. 8791). Pakai saat portal/gateway tidak bisa diakses — cepat lihat siapa yang listen dan di port mana. Read-only, hasil terbatas pada socket TCP listening IPv4+IPv6 milik user ini."""
    entries = []
    for ln in _run(["ss", "-ltnpH"]).splitlines():
        parts = ln.split()
        if len(parts) < 4 or ":" not in parts[3]:
            continue
        try:
            pno = int(parts[3].rsplit(":", 1)[1])
        except ValueError:
            continue
        proc = ""
        if "users:" in ln:
            proc = ln.split("users:", 1)[1].strip()[:140]
        entries.append({"port": pno, "state": parts[0], "local": parts[3],
                        "process": proc})
    if port is not None:
        hits = [e for e in entries if e["port"] == port]
        return {"port": port, "listening": bool(hits), "entries": hits}
    return {"listening_ports": sorted({e["port"] for e in entries}),
            "entries": entries}


# journalctl -p tidak valid -> exit 0 + "Unknown log level" (empiris 1 Okt 2026):
# pesan itu pernah bocor keluar sebagai LOG PALSU. Validasi allow-list dulu.
JOURNAL_LEVELS = frozenset({
    "", "emerg", "alert", "crit", "err", "error", "warning", "warn", "notice",
    "info", "debug", "0", "1", "2", "3", "4", "5", "6", "7",
})


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
def gateway_logs(n: int = 100, level: str = "", contains: str = "") -> dict:
    """Tail journal unit hermes-gateway dengan filter severity (emerg..debug atau angka 0-7, divalidasi lebih dulu — level salah memunculkan ValueError, bukan log palsu) dan/atau substring 'contains'; semua token panjang di-redact sebelum keluar server. Pakai saat gateway aneh: cari pola error/warning di sekitar waktu kejadian. 'n' 1-500 baris; read-only."""
    level = str(level).lower().strip()
    if level not in JOURNAL_LEVELS:
        raise ValueError(
            f"level '{level}' tidak valid — pilih emerg|alert|crit|err|warning|"
            "notice|info|debug (atau angka 0-7)"
        )
    cmd = ["journalctl", "--user", "-u", "hermes-gateway",
           "-n", str(max(1, min(n, 500))), "--no-pager", "-o", "short-iso", "-q"]
    if level:
        cmd += ["-p", level]
    raw = _run(cmd, user=True, timeout=20)
    if raw.startswith("error:"):
        return {"error": raw}
    lines = raw.splitlines()
    if contains:
        needle = contains.lower()
        lines = [ln for ln in lines if needle in ln.lower()]
    lines = [_LONG_TOKEN_RE.sub("[REDACTED]", ln) for ln in lines]
    return {"requested": n, "level": level or None, "contains": contains or None,
            "returned": len(lines),
            "lines": [ln.rstrip() for ln in lines[-min(len(lines), 200):]]}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
def config_view(section: str = "") -> dict:
    """Baca ~/.hermes/config.yaml sebagai dict ter-olah — 'section' memilih top-level key (mis. 'mcp_servers', 'model'); kosong untuk seluruh file. Secret otomatis di-redact (token >=40 char + hint key/password/secret/token). Pakai saat perlu cek setting atau deteksi bentrok konfigurasi tanpa membuka file mentah. Read-only; tidak pernah menampilkan kredensial asli."""
    try:
        with open(CONFIG_PATH, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        return {"error": f"config unreadable: {exc}"}
    if not isinstance(data, dict):
        return {"error": "config root is not a mapping"}
    if section:
        if section not in data:
            return {"error": f"section '{section}' not found",
                    "sections": sorted(str(k) for k in data)}
        return {"path": CONFIG_PATH, "section": section,
                "config": _redact({section: data[section]})}
    return {"path": CONFIG_PATH, "sections": sorted(str(k) for k in data),
            "config": _redact(data)}


if __name__ == "__main__":
    mcp.run()
