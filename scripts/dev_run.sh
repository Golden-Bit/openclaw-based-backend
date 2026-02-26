#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f ".env" ]]; then
  echo "Missing .env in repo root. Copy .env.example -> .env and edit." >&2
  exit 1
fi

set -a
source .env
set +a

uvicorn app.main:app --host 0.0.0.0 --port "${BFF_PORT:-8000}" --reload \
  --reload-exclude "infra/*" --reload-exclude "infra/**"