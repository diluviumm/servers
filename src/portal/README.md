# Hermes Portal MCP Server

Gerbang output desktop: **screenshot layar** (via Niri
`screenshot-screen --write-to-disk`) + **clipboard** read/write
(wl-clipboard). Tanpa dialog consent, tanpa instalasi tambahan
(`niri` + `wl-clipboard` sudah ada di mesin target).

## Tools

| Tool | Highlight |
|---|---|
| `screenshot` | Screenshot layar fokus ke PNG; `save_to` path (dibuat otomatis), default `~/Pictures/Screenshots/hermes-<waktu>.png`; menunggu file muncul + laporkan `size_bytes` |
| `clipboard_read` | Baca teks clipboard (`wl-paste`); `empty=true` bila tak berisi teks |
| `clipboard_write` | Tulis teks ke clipboard (`wl-copy`) — menimpa isi clipboard |

## Requirements

- `niri` (compositor) + `wl-clipboard` (`wl-paste`/`wl-copy`)
- Runtime Python ≥3.10 dengan paket `mcp<2`

## Run standalone

```bash
python3 server.py   # MCP over stdio
```

## Register ke Hermes

```bash
~/.hermes/mcp-servers/venv/bin/python /path/ke/src/portal/server.py
```

## Catatan

- Screenshot juga masuk clipboard sistem sebagai efek samping native Niri.
- `clipboard_write` menimpa clipboard user — gunakan hanya saat diminta.
