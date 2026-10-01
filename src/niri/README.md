# Hermes Niri MCP Server

Introspection + safe window-manager actions untuk compositor **Niri**
(hanya `niri msg` JSON IPC — tanpa `spawn`, tanpa `quit`/`power-off`).

## Tools

| Tool | Highlight |
|---|---|
| `overview` | Peta desktop: outputs, workspace (aktif/fokus), jendela (id/app/judul/workspace), jendela fokus |
| `focus_workspace` | Fokus workspace by index/nama |
| `focus_window` | Fokus jendela by id |
| `move_window_to_workspace` | Pindahkan jendela FOKUS ke workspace lain |
| `close_window` | Tutup jendela by id (`close-window --id`, tanpa fokus) |

## Requirements

- `niri` berjalan (terdeteksi via `niri msg`)
- Runtime Python ≥3.10 dengan paket `mcp<2`

## Run standalone

```bash
python3 server.py   # MCP over stdio
```

## Register ke Hermes

```bash
~/.hermes/mcp-servers/venv/bin/python /path/ke/src/niri/server.py
```

## Tool annotations (MCP)

| Annotation | Tools |
|---|---|
| `readOnlyHint=true` | `overview` |
| `destructiveHint=false`, `idempotentHint=true` | `focus_workspace`, `focus_window`, `move_window_to_workspace` |
| `destructiveHint=true` | `close_window` (jendela bisa ada pekerjaan tak tersimpan) |

## Urutan pemakaian yang benar

1. `overview` dulu → dapat `id` jendela & index/nama workspace.
2. `focus_window` / `focus_workspace` (idempotent — aman diulang).
3. `move_window_to_workspace` memindahkan jendela yang **sedang fokus**
   (focus dulu bila tujuannya bukan jendela fokus).
4. `close_window` terakhir — satu-satunya aksi destruktif.

## Catatan keamanan

Action yang disediakan **hanya** yang terbalik-arah (focus/move/close by id
explicit) — tanpa eksekusi perintah, tanpa mematikan sesi. Selalu baca
`overview` sebelum action.
