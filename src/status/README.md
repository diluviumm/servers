# Hermes Status MCP Server

Health checks for a self-hosted Hermes Agent stack (gateway, Cloudflare
tunnel, portal, systemd units, ports) plus a log tail helper.

## Tools

| Tool | Purpose |
|---|---|
| `health()` | JSON health of gateway, tunnel, portal, Hindsight, failed systemd units, known ports |
| `recent_errors(n)` | Tail `~/.hermes/logs/errors.log` |

## Run

```bash
python3 server.py          # MCP over stdio (requires the `mcp` package)
```

Register with Hermes:

```bash
printf 'y\n' | hermes mcp add status --command python3 --args /abs/path/to/server.py
```
