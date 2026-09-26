#!/usr/bin/env bash
# check.sh — satu perintah: pytest+cov, ruff, pyright untuk 4 paket custom fork.
# Dipakai manual (scripts/check.sh) — pre-push hook menjalankan versi pytest+cov saja.
set -euo pipefail
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
