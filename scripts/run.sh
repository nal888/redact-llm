#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export PORT="${PORT:-8181}"
export ENGAGEMENT_ID="${ENGAGEMENT_ID:-default}"

if [[ "$ENGAGEMENT_ID" == "default" ]]; then
  echo "⚠️  ENGAGEMENT_ID=default — set a unique name per client!"
  echo "   export ENGAGEMENT_ID=<client-name>-<year>-<quarter>"
  echo
fi

exec .venv/bin/uvicorn anon_proxy.server:app --app-dir "$(pwd)" --host 127.0.0.1 --port "$PORT" --log-level info
