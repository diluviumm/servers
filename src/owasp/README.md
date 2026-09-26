# Hermes OWASP MCP Server

Wraps locally installed scanners — **gitleaks** (secrets), **trivy**
(vulns / secrets / misconfig), **nuclei** (web templates) — as MCP tools so
an agent can run security checks on demand.

## Tools

| Tool | Purpose |
|---|---|
| `gitleaks_scan(path)` | Secret scan of a repo/directory |
| `trivy_fs(path)` | Vulns + secrets + misconfig on a path |
| `trivy_image(image)` | CVE scan of a container image |
| `nuclei_scan(target)` | Web template scan — **allow-listed hosts only** (loopback + own domain, enforced in code) |

## Safety rails

* nuclei target allow-list is enforced programmatically (not by prose).
* all subprocesses carry hard timeouts; output is a compact summary,
  never raw multi-MB reports.

## Run

```bash
python3 server.py          # MCP over stdio (requires the `mcp` package)
```

Register with Hermes:

```bash
printf 'y\n' | hermes mcp add owasp --command python3 --args /abs/path/to/server.py
```
