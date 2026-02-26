#!/usr/bin/env bash
set -euo pipefail

# Runs the backend on the HOST (not in Docker), using .env in repo root.
# Requires Python + venv.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f ".env" ]]; then
  echo "Missing .env in repo root. Copy .env.example -> .env and edit." >&2
  exit 1
fi

export $(grep -v '^#' .env | xargs) || true

# If you are using a venv:
#   python -m venv .venv
#   source .venv/bin/activate
#   pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port "${BFF_PORT:-8000}"
