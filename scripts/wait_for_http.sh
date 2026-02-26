#!/usr/bin/env bash
set -euo pipefail

URL="${1:-}"
TIMEOUT_SECS="${2:-60}"

if [[ -z "$URL" ]]; then
  echo "Usage: $0 <url> [timeout_secs]" >&2
  exit 2
fi

start="$(date +%s)"
while true; do
  if curl -fsS "$URL" >/dev/null 2>&1; then
    echo "OK: $URL"
    exit 0
  fi
  now="$(date +%s)"
  if (( now - start >= TIMEOUT_SECS )); then
    echo "ERROR: Timeout waiting for $URL" >&2
    exit 1
  fi
  sleep 1
done
