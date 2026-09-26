"""Hermes OWASP MCP server.

Wraps the security scanners already installed on the host (gitleaks, trivy,
nuclei, bearer) as MCP tools so an agent can run them on demand.

Safety rails enforced in code, not prose:
  * `nuclei_scan()` only accepts loopback / own-domain targets (allow-list).
  * every tool output is a compact summary, never raw multi-MB dumps.
  * all subprocesses carry hard timeouts.
  * trivy DB is auto-refreshed when older than 48h (stale DB = missed CVEs).

Run standalone:  python3 server.py   (MCP over stdio)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hermes-owasp")

# Targets nuclei may ever scan: loopback + own domain. Enforced below.
NUCLEI_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "ishmly.space"}

SCANNERS = {
    "gitleaks": "/home/mael/.local/bin/gitleaks",
    "trivy": "/home/mael/.local/bin/trivy",
    "nuclei": "/home/mael/.local/bin/nuclei",
    "bearer": "/home/mael/.local/bin/bearer",
}

STATE_DIR = Path(os.path.expanduser("~/.hermes/mcp-servers/state"))
TRIVY_DB_META = Path(os.path.expanduser("~/.cache/trivy/db/metadata.json"))
CUSTOM_TEMPLATES = Path(__file__).resolve().parent / "templates"
GITLEAKS_BASELINE = STATE_DIR / "gitleaks-baseline.json"
TRIVY_DB_MAX_AGE_H = 48


def _bin(name: str) -> str:
    import shutil

    p = SCANNERS[name]
    if os.path.exists(p):
        return p
    found = shutil.which(name)
    if not found:
        raise RuntimeError(f"{name} not installed")
    return found


def _run(cmd: list[str], timeout: int) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           check=False)
        return {"code": r.returncode, "out": r.stdout, "err": r.stderr}
    except subprocess.TimeoutExpired:
        return {"code": -1, "out": "", "err": f"timeout after {timeout}s"}
    except Exception as exc:  # noqa: BLE001
        return {"code": -1, "out": "", "err": str(exc)[:200]}


def _brief(findings: list, limit: int = 10) -> dict:
    return {
        "count": len(findings),
        "sample": [
            {k: f.get(k) for k in ("RuleID", "Description", "Severity", "Target",
                                   "VulnerabilityID", "PkgName") if f.get(k)}
            for f in findings[:limit]
        ],
    }


def _resolve_output(output_file: str | None, suffix: str) -> str:
    if output_file:
        path = Path(os.path.expanduser(output_file))
        path.parent.mkdir(parents=True, exist_ok=True)
        return str(path)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    return str(STATE_DIR / f"last-scan{suffix}")


def _write_md(path_str: str, title: str, sections: list[tuple[str, str]]) -> str:
    """Write a human-readable markdown summary of a scan."""
    path = Path(os.path.expanduser(path_str))
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# {title}", "", f"_generated: {time.strftime('%Y-%m-%d %H:%M:%S')}_", ""]
    for heading, body in sections:
        lines += [f"## {heading}", "", body, ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


def _md_table(rows: list[dict], cols: list[str]) -> str:
    if not rows:
        return "_no findings_"
    head = "| " + " | ".join(cols) + " |"
    sep = "|" + "|".join(["---"] * len(cols)) + "|"
    body = [
        "| " + " | ".join(str(r.get(c, "")).replace("|", "\\|")[:80] for c in cols) + " |"
        for r in rows
    ]
    return "\n".join([head, sep, *body])


def _trivy_db_age_h() -> float | None:
    try:
        meta = json.loads(TRIVY_DB_META.read_text(encoding="utf-8"))
        ts = time.mktime(time.strptime((meta.get("UpdatedAt") or "")[:19],
                                       "%Y-%m-%dT%H:%M:%S"))
        return round((time.time() - ts) / 3600, 1)
    except Exception:  # noqa: BLE001
        return None


def _ensure_trivy_db() -> dict:
    """Refresh the trivy vulnerability DB when older than TRIVY_DB_MAX_AGE_H.

    A stale DB silently misses CVEs — this is the fix for that trap.
    """
    age = _trivy_db_age_h()
    if age is not None and age < TRIVY_DB_MAX_AGE_H:
        return {"age_h": age, "refreshed": False, "stale": False}
    result = _run([_bin("trivy"), "--download-db-only", "--quiet"], timeout=300)
    if result["code"] != 0:
        result = _run([_bin("trivy"), "db", "download"], timeout=300)
    new_age = _trivy_db_age_h()
    return {
        "age_h_before": age,
        "age_h": new_age,
        "refreshed": result["code"] == 0,
        "stale": new_age is None or new_age >= TRIVY_DB_MAX_AGE_H,
        "detail": (result["err"] or result["out"])[:200] if result["code"] != 0 else "",
    }


def _count_sarif(text: str) -> int | None:
    try:
        data = json.loads(text)
        return sum(len(r.get("results", [])) for r in data.get("runs", []))
    except Exception:  # noqa: BLE001
        return None


def _count_junit(text: str) -> int | None:
    m = re.search(r'tests="(\d+)"[^>]*failures="(\d+)"', text)
    if m:
        return int(m.group(2))
    return len(re.findall(r"<failure", text)) or None


@mcp.tool()
def gitleaks_scan(path: str, mode: str = "dir", timeout_s: int = 120,
                  format: str = "json", output_file: str | None = None,
                  use_baseline: bool = False, save_baseline: bool = False,
                  report_md: str | None = None) -> dict:
    """Scan for leaked secrets (gitleaks). mode: 'dir' (working tree) or 'git' (full history).
    format: json|sarif|junit. use_baseline skips known findings (state/gitleaks-baseline.json);
    save_baseline stores the current report as baseline. report_md writes a markdown summary."""
    if mode not in ("dir", "git"):
        raise ValueError("mode must be 'dir' or 'git'")
    if format not in ("json", "sarif", "junit"):
        raise ValueError("format must be json|sarif|junit")

    cmd = [_bin("gitleaks"), mode, path, "--report-format", format,
           "--no-banner"]
    if format == "json" and not output_file:
        cmd += ["--report-path", "/dev/stdout"]
    if use_baseline and GITLEAKS_BASELINE.exists():
        cmd += ["--baseline-path", str(GITLEAKS_BASELINE)]
    if output_file or format != "json":
        cmd += ["--report-path", _resolve_output(output_file, f".gitleaks.{format}")]

    result = _run(cmd, timeout=min(timeout_s, 300))
    if result["code"] == -1:
        return {"error": result["err"]}

    out: dict = {"mode": mode, "format": format, "exit": result["code"],
                 "baseline_used": use_baseline and GITLEAKS_BASELINE.exists()}

    if format == "json":
        try:
            findings = json.loads(result["out"] or "[]")
        except json.JSONDecodeError:
            return {**out, "error": (result["err"][:300] or "no report")}
        out.update(_brief(findings))
        out["clean"] = result["code"] in (0,) and not findings
        if save_baseline:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            GITLEAKS_BASELINE.write_text(json.dumps(findings), encoding="utf-8")
            out["baseline_saved"] = len(findings)
        if report_md:
            status_txt = (f"{'CLEAN — 0' if not findings else str(len(findings)) + ' finding(s)'}"
                          f" · mode={mode} · exit={result['code']}")
            cols = (["RuleID", "Description", "File", "Secret"]
                    if findings and isinstance(findings[0], dict) else ["v"])
            rows = [f if isinstance(f, dict) else {"v": f} for f in findings[:20]]
            out["report_md"] = _write_md(
                report_md, "Gitleaks scan",
                [("Result", status_txt), ("Findings", _md_table(rows, cols))],
            )
    elif format == "sarif":
        saved = _resolve_output(output_file, ".gitleaks.sarif")
        if os.path.exists(saved):
            with open(saved, encoding="utf-8", errors="replace") as fh:
                out["findings"] = _count_sarif(fh.read())
        out["saved_to"] = saved
    else:
        saved = _resolve_output(output_file, ".gitleaks.junit.xml")
        if os.path.exists(saved):
            with open(saved, encoding="utf-8", errors="replace") as fh:
                out["failures"] = _count_junit(fh.read())
        out["saved_to"] = saved
    return out


@mcp.tool()
def bearer_scan(path: str, timeout_s: int = 300, output_file: str | None = None,
                report_md: str | None = None) -> dict:
    """Scan source code for hard-coded secrets/PII (bearer). JSON summary; report can be saved."""
    cmd = [_bin("bearer"), "scan", path, "--format", "json", "--hide-progress-bar",
           "--no-color"]
    if output_file:
        cmd += ["--output", _resolve_output(output_file, ".bearer.json")]
    result = _run(cmd, timeout=min(timeout_s, 600))
    if result["code"] == -1:
        return {"error": result["err"]}

    out: dict = {"exit": result["code"]}
    try:
        data = json.loads(result["out"] or "{}")
    except json.JSONDecodeError:
        return {**out, "error": (result["err"][:300] or "unparseable bearer output")}

    files = data.get("files") or []
    findings = []
    for f in files:
        for item in f.get("findings") or []:
            findings.append({"file": f.get("location", {}).get("path") or f.get("path"),
                             "detector": item.get("detector_id") or item.get("detector"),
                             "line": item.get("line_number") or item.get("line")})
    summary = data.get("leak_summary") or {}
    out.update({"findings": len(findings), "severity": summary or None,
                "sample": findings[:10],
                "report_keys": sorted(data.keys())[:12] if not findings and data else None})
    if report_md:
        out["report_md"] = _write_md(
            report_md, "Bearer secret scan",
            [("Result", f"{len(findings)} finding(s) · exit={result['code']}"),
             ("Findings", _md_table(findings[:20], ["file", "detector", "line"]))],
        )
    return out


@mcp.tool()
def trivy_fs(path: str, timeout_s: int = 300, format: str = "json",
             output_file: str | None = None, report_md: str | None = None) -> dict:
    """Scan a filesystem/path for vulnerabilities, secrets and misconfig (trivy).
    Auto-refreshes the vuln DB when older than 48h. format: json|sarif|junit."""
    if format not in ("json", "sarif", "junit"):
        raise ValueError("format must be json|sarif|junit")

    db = _ensure_trivy_db()
    if format != "json":
        out_path = _resolve_output(output_file, f".trivy.{format}")
        result = _run([_bin("trivy"), "fs", "--scanners", "vuln,secret,misconfig",
                       "--format", format, "--output", out_path, "--quiet", path],
                      timeout=min(timeout_s, 600))
        if result["code"] == -1:
            return {"error": result["err"], "db": db}
        out: dict = {"format": format, "exit": result["code"], "saved_to": out_path,
                     "db": db}
        if format == "sarif" and os.path.exists(out_path):
            with open(out_path, encoding="utf-8", errors="replace") as fh:
                out["findings"] = _count_sarif(fh.read())
        elif format == "junit" and os.path.exists(out_path):
            with open(out_path, encoding="utf-8", errors="replace") as fh:
                out["failures"] = _count_junit(fh.read())
        return out

    result = _run([_bin("trivy"), "fs", "--scanners", "vuln,secret,misconfig",
                   "--format", "json", "--quiet", path], timeout=min(timeout_s, 600))
    if result["code"] == -1:
        return {"error": result["err"], "db": db}
    try:
        data = json.loads(result["out"] or "{}")
    except json.JSONDecodeError:
        return {"error": (result["err"][:300] or "unparseable output"),
                "exit": result["code"], "db": db}
    vulns, secrets = [], []
    for res in data.get("Results", []) or []:
        vulns += res.get("Vulnerabilities") or []
        secrets += res.get("Secrets") or []
    out = {"vulnerabilities": _brief(vulns), "secrets": _brief(secrets),
           "exit": result["code"], "db": db}
    if report_md:
        out["report_md"] = _write_md(
            report_md, "Trivy filesystem scan",
            [("Vulnerabilities", f"{len(vulns)} · DB age {db.get('age_h')}h"),
             ("Top CVEs", _md_table(vulns[:15],
                                    ["VulnerabilityID", "PkgName", "Severity"])),
             ("Secrets", _md_table(secrets[:10], ["RuleID", "Target"]))],
        )
    return out


@mcp.tool()
def trivy_image(image: str, timeout_s: int = 300, format: str = "json") -> dict:
    """Scan a container image for CVEs and secrets (trivy image). format: json|sarif."""
    if format not in ("json", "sarif"):
        raise ValueError("format must be json or sarif")
    db = _ensure_trivy_db()

    if format == "sarif":
        out_path = _resolve_output(None, ".trivy-image.sarif")
        result = _run([_bin("trivy"), "image", "--scanners", "vuln,secret",
                       "--format", "sarif", "--output", out_path, "--quiet", image],
                      timeout=min(timeout_s, 600))
        out: dict = {"image": image, "format": "sarif", "exit": result["code"],
                     "saved_to": out_path, "db": db}
        if result["code"] == 0 and os.path.exists(out_path):
            with open(out_path, encoding="utf-8", errors="replace") as fh:
                out["findings"] = _count_sarif(fh.read())
        return out

    result = _run([_bin("trivy"), "image", "--scanners", "vuln,secret",
                   "--format", "json", "--quiet", image], timeout=min(timeout_s, 600))
    if result["code"] == -1:
        return {"error": result["err"], "db": db}
    try:
        data = json.loads(result["out"] or "{}")
    except json.JSONDecodeError:
        return {"error": (result["err"][:300] or "unparseable output"),
                "exit": result["code"], "db": db}
    vulns = []
    for res in data.get("Results", []) or []:
        vulns += res.get("Vulnerabilities") or []
    sev: dict[str, int] = {}
    for v in vulns:
        s = v.get("Severity", "?")
        sev[s] = sev.get(s, 0) + 1
    return {"image": image, "severity_counts": sev,
            "sample": _brief(vulns)["sample"], "exit": result["code"], "db": db}


@mcp.tool()
def nuclei_scan(target: str, severity: str = "high,critical", timeout_s: int = 300,
                templates: str | None = None, report_md: str | None = None) -> dict:
    """Scan an ALLOW-LISTED target (loopback + own domain only) with nuclei.
    Custom templates folder (src/owasp/templates) is always included when present;
    pass `templates` to add another local template directory."""
    from urllib.parse import urlparse

    host = urlparse(target if "://" in target else f"http://{target}").hostname or ""
    if host not in NUCLEI_ALLOWED_HOSTS:
        raise ValueError(
            f"target host '{host}' not in allow-list {sorted(NUCLEI_ALLOWED_HOSTS)} — "
            "nuclei only scans this machine's own assets"
        )

    cmd = [_bin("nuclei"), "-u", target, "-severity", severity,
           "-jsonl", "-silent", "-timeout", "10"]
    tpl_dirs = []
    if CUSTOM_TEMPLATES.is_dir() and any(CUSTOM_TEMPLATES.glob("*.yaml")):
        tpl_dirs.append(str(CUSTOM_TEMPLATES))
    if templates:
        extra = Path(os.path.expanduser(templates))
        if not extra.is_dir():
            raise ValueError(f"templates path '{templates}' is not a directory")
        tpl_dirs.append(str(extra))
    if tpl_dirs:
        cmd += ["-t", ",".join(tpl_dirs)]

    result = _run(cmd, timeout=min(timeout_s, 600))
    if result["code"] == -1:
        return {"error": result["err"]}
    findings = []
    for ln in (result["out"] or "").splitlines():
        try:
            j = json.loads(ln)
            findings.append({
                "id": j.get("templateID"),
                "severity": (j.get("info") or {}).get("severity"),
                "name": (j.get("info") or {}).get("name"),
                "url": j.get("matched-at"),
            })
        except json.JSONDecodeError:
            continue
    out = {"target": target, "count": len(findings),
           "findings": findings[:15], "exit": result["code"],
           "templates_used": tpl_dirs or "builtin only"}
    if report_md:
        out["report_md"] = _write_md(
            report_md, "Nuclei scan",
            [("Result", f"{len(findings)} finding(s) · target={target} · exit={result['code']}"),
             ("Findings", _md_table(findings[:20], ["id", "severity", "name", "url"]))],
        )
    return out


if __name__ == "__main__":
    mcp.run()
