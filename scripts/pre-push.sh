#!/usr/bin/env bash
# pre-push — suite 4 paket custom fork (pytest + coverage gate).
# Hermetic: buang env bocor (PYTHONPATH Hermes 3.14 vs py3.10 uv run) agar
# push dari dalam sesi Hermes/cron tetap valid, sama seperti push dari terminal.
set -euo pipefail
for v in PYTHONPATH PYTHONHOME VIRTUAL_ENV LD_LIBRARY_PATH LD_PRELOAD UV_PROJECT_ENVIRONMENT; do
  unset "$v" 2>/dev/null || true
done
export PATH="$HOME/.local/bin:$PATH"
cd "$(git rev-parse --show-toplevel)"
for p in status owasp niri portal; do
  (cd "src/$p" && uv run pytest -q --cov=.) || {
    echo "pre-push: $p GAGAL — push dibatalkan" >&2
    exit 1
  }
done
echo "pre-push: 4 paket OK (pytest + coverage gate)"
