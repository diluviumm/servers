"""Hermes OWASP MCP server.

Wraps the security scanners already installed on the host (gitleaks, trivy,
nuclei) as MCP tools so an agent can run them on demand.

Safety rails enforced in code, not prose:
  * `nuclei()` only accepts loopback / own-domain targets (allow-list).
  * every tool output is a compact summary, never raw multi-MB dumps.
  * all subprocesses carry hard timeouts.

Run standalone:  python3 server.py   (MCP over stdio)
"""

from __future__ import annotations

import json
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hermes-owasp")

# Targets nuclei may ever scan: loopback + own domain. Enforced below.
NUCLEI_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "ishmly.space"}

SCANNERS = {"gitleaks": "/home/mael/.local/bin/gitleaks",
            "trivy": "/home/mael/.local/bin/trivy",
            "nuclei": "/home/mael/.local/bin/nuclei"}


def _bin(name: str) -> str:
    import shutil
    import os
    p = SCANNERS[name]
    if os.path.exists(p):
        return p
    found = shutil.which(name)
    if not found:
        raise RuntimeError(f"{name} not installed")
    return found


def _run(cmd: list[str], timeout: int) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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


@mcp.tool()
def gitleaks_scan(path: str, timeout_s: int = 120) -> dict:
    """Scan a git repo or directory for leaked secrets (gitleaks)."""
    result = _run([_bin("gitleaks"), "dir", path,
                   "--report-format", "json", "--report-path", "/dev/stdout",
                   "--no-banner"], timeout=min(timeout_s, 300))
    if result["code"] == -1:
        return {"error": result["err"]}
    try:
        findings = json.loads(result["out"] or "[]")
    except json.JSONDecodeError:
        return {"error": result["err"][:300] or "no report", "exit": result["code"]}
    out = _brief(findings)
    out["clean"] = result["code"] in (0,) and not findings
    out["exit"] = result["code"]
    return out


@mcp.tool()
def trivy_fs(path: str, timeout_s: int = 300) -> dict:
    """Scan a filesystem/path for vulnerabilities, secrets and misconfig (trivy)."""
    result = _run([_bin("trivy"), "fs", "--scanners", "vuln,secret,misconfig",
                   "--format", "json", "--quiet", path], timeout=min(timeout_s, 600))
    if result["code"] == -1:
        return {"error": result["err"]}
    try:
        data = json.loads(result["out"] or "{}")
    except json.JSONDecodeError:
        return {"error": result["err"][:300] or "unparseable output", "exit": result["code"]}
    vulns, secrets = [], []
    for res in data.get("Results", []) or []:
        vulns += res.get("Vulnerabilities") or []
        secrets += res.get("Secrets") or []
    return {
        "vulnerabilities": _brief(vulns),
        "secrets": _brief(secrets),
        "exit": result["code"],
    }


@mcp.tool()
def trivy_image(image: str, timeout_s: int = 300) -> dict:
    """Scan a container image for CVEs and secrets (trivy image)."""
    result = _run([_bin("trivy"), "image", "--scanners", "vuln,secret",
                   "--format", "json", "--quiet", image], timeout=min(timeout_s, 600))
    if result["code"] == -1:
        return {"error": result["err"]}
    try:
        data = json.loads(result["out"] or "{}")
    except json.JSONDecodeError:
        return {"error": result["err"][:300] or "unparseable output", "exit": result["code"]}
    vulns = []
    for res in data.get("Results", []) or []:
        vulns += res.get("Vulnerabilities") or []
    sev: dict[str, int] = {}
    for v in vulns:
        s = v.get("Severity", "?")
        sev[s] = sev.get(s, 0) + 1
    return {"image": image, "severity_counts": sev,
            "sample": _brief(vulns)["sample"], "exit": result["code"]}


@mcp.tool()
def nuclei_scan(target: str, severity: str = "high,critical", timeout_s: int = 300) -> dict:
    """Scan an ALLOW-LISTED target (loopback + own domain only) with nuclei."""
    from urllib.parse import urlparse
    host = urlparse(target if "://" in target else f"http://{target}").hostname or ""
    if host not in NUCLEI_ALLOWED_HOSTS:
        raise ValueError(
            f"target host '{host}' not in allow-list {sorted(NUCLEI_ALLOWED_HOSTS)} — "
            "nuclei only scans this machine's own assets"
        )
    result = _run([_bin("nuclei"), "-u", target, "-severity", severity,
                   "-jsonl", "-silent", "-timeout", "10"], timeout=min(timeout_s, 600))
    if result["code"] == -1:
        return {"error": result["err"]}
    findings = []
    for ln in (result["out"] or "").splitlines():
        try:
            j = json.loads(ln)
            findings.append({"id": j.get("templateID"), "severity": j.get("info", {}).get("severity"),
                             "name": j.get("info", {}).get("name"), "url": j.get("matched-at")})
        except json.JSONDecodeError:
            continue
    return {"target": target, "count": len(findings), "findings": findings[:15],
            "exit": result["code"]}


if __name__ == "__main__":
    mcp.run()
