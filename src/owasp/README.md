# Hermes OWASP MCP Server

Wraps locally installed scanners — **gitleaks**, **trivy**, **nuclei**,
**bearer** — as MCP tools so an agent can run security checks on demand.

## Tools

| Tool | Highlights |
|---|---|
| `gitleaks_scan` | `mode=dir\|git` (working tree or full history), `format=json\|sarif\|junit`, `use_baseline` / `save_baseline` against `~/.hermes/mcp-servers/state/gitleaks-baseline.json`, `report_md` for a markdown summary. |
| `bearer_scan` | Hard-coded secrets/PII via bearer; JSON summary, `output_file`, `report_md`. |
| `trivy_fs` | vuln+secret+misconfig; **auto-refreshes the vuln DB when older than 48h** (stale DB misses CVEs); `format=json\|sarif\|junit`, `report_md`. |
| `trivy_image` | Image CVE/severity counts; `format=json\|sarif`. |
| `nuclei_scan` | **Allow-list enforced in code**: loopback + own domain only. Always includes `templates/` (custom) when present; `templates=` adds another dir. `report_md`. |

## Tool annotations

All five tools are `readOnlyHint=true` (they scan, never modify the target).
`trivy_image` and `nuclei_scan` additionally carry `openWorldHint=true` —
they reach the network (image registry / scan target).

## How to use (example prompts for the agent)

- "Scan this repo for leaked secrets" → `gitleaks_scan(path=".", mode="git")`
- "Any known CVEs in my dependencies?" → `trivy_fs(path=".", report_md=True)`
- "Is my image safe to ship?" → `trivy_image(image="myapp:1.2.3")`
- "Check https://ishmly.space security headers" → `nuclei_scan(host="https://ishmly.space")`
  (anything outside the code allow-list raises `ValueError` — by design)

## Safety rails (code, not prose)

* nuclei target allow-list raises `ValueError` for any host outside it.
* all subprocesses carry hard timeouts; output is a compact summary,
  never raw multi-MB reports.
* reports/state live under `~/.hermes/mcp-servers/state/`.
* custom nuclei templates: `templates/*.yaml` (e.g. `security-headers.yaml`).

## Run

```bash
python3 server.py          # MCP over stdio (requires the `mcp<2` package)
pytest tests/              # scanners mocked, allow-list asserted
```

Register with Hermes (use the shared venv, not bare python3 — the MCP child
env hides user-site packages):

```bash
printf 'y\n' | hermes mcp add owasp \
  --command ~/.hermes/mcp-servers/venv/bin/python --args /abs/path/to/server.py
```
