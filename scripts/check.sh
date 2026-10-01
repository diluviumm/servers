#!/usr/bin/env bash
# check.sh — satu perintah: pytest+cov, ruff, pyright untuk 4 paket custom fork.
# Dipakai manual (scripts/check.sh) — pre-push hook menjalankan versi pytest+cov saja.
set -euo pipefail
# Hermetic: buang env yang bocor dari sesi Hermes/cron. PYTHONPATH menunjuk ke
# site-packages Python 3.14 Hermes → py3.10 uv run gagal import pydantic_core.
for v in PYTHONPATH PYTHONHOME VIRTUAL_ENV LD_LIBRARY_PATH LD_PRELOAD UV_PROJECT_ENVIRONMENT; do
  unset "$v" 2>/dev/null || true
done
export PATH="$HOME/.local/bin:$PATH"
cd "$(git rev-parse --show-toplevel)"
fail=0
for p in status owasp niri portal; do
  echo "== $p =="
  (cd "src/$p" \
    && uv run pytest -q --cov=. 2>&1 | grep -E 'Required|passed|failed' \
    && uv run ruff check . 2>&1 | tail -1 \
    && uv run --frozen pyright 2>&1 | tail -1) || { echo "== $p GAGAL =="; fail=1; }
done
[ "$fail" -eq 0 ] && echo "CHECK-SEMUA-OK (4 paket: pytest+cov, ruff, pyright)" || exit 1
