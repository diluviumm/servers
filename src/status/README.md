# Hermes Status MCP Server

Health checks for a self-hosted Hermes Agent stack (gateway, Cloudflare
tunnel, portal, systemd units, ports, disk, RAM, load, trivy DB age) plus a
pattern-grouped error triage helper.

## Tools

| Tool | Purpose |
|---|---|
| `health` | Full infra snapshot: gateway (active/pids/uptime/heartbeat age), tunnel process, portal + Hindsight HTTP, failed systemd units, known ports, disk usage (warn ≥90%), memory, load average, trivy DB age/stale flag. `ok` summarizes. |
| `recent_errors(n)` | Tail `errors.log`, normalize volatile parts (timestamps/UUIDs/hex/numbers), return top error **patterns with frequencies** + raw tail. |

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
