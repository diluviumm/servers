# Hermes Status MCP Server

Health checks for a self-hosted Hermes Agent stack (gateway, Cloudflare
tunnel, portal, systemd units, ports, disk, RAM, load, trivy DB age) plus a
pattern-grouped error triage helper.

## Tools

All six tools are annotated `readOnlyHint=true` — safe to call at any time,
they never change system state.

| Tool | Purpose |
|---|---|
| `health` | Full infra snapshot: gateway (active/pids/uptime/heartbeat age), tunnel process, portal + Hindsight HTTP, failed systemd units, known ports, disk usage (warn ≥90%), memory, load average, trivy DB age/stale flag. `ok` summarizes. |
| `recent_errors(n)` | Tail `errors.log`, normalize volatile parts (timestamps/UUIDs/hex/numbers), return top error **patterns with frequencies** + raw tail. Tolerant to unreadable logs (returns `error` field, never crashes). |
| `services(pattern)` | List `systemctl --user` units matching the glob (default `hermes-*`), split into healthy / `inactive (timer)` by-design / genuinely **unhealthy** + the `failed` list. |
| `ports(port=None)` | `ss -ltnpH` snapshot: listening ports with owning processes (filter by exact `port`). |
| `gateway_logs(n, level, contains)` | Tail `journalctl --user -u hermes-gateway`; filter by severity (`emerg..debug` or 0-7 — **validated, an invalid level raises `ValueError` instead of returning journalctl's error text as fake logs**) and/or substring; long tokens are redacted. |
| `config_view(section)` | Parse `~/.hermes/config.yaml` (top-level `section` or whole file) with secrets **redacted** (tokens ≥40 chars + key/token/password/secret hints). |

## Run

```bash
python3 server.py          # MCP over stdio (requires the `mcp<2` package)
pytest tests/              # infra is mocked; no live services needed
```

Register with Hermes (use the shared venv, not bare python3 — the MCP child
env hides user-site packages):

```bash
printf 'y\n' | hermes mcp add status \
  --command ~/.hermes/mcp-servers/venv/bin/python --args /abs/path/to/server.py
```

## Notes

- `systemctl --user` runs with a synthesized session bus env, so the server
  works when launched from a filtered MCP child environment.
