#!/usr/bin/env bash

# Carica .env del repo (se presente)
if [[ -f "$ROOT_DIR/.env" ]]; then
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

"$ROOT_DIR/scripts/start_infra.sh"
"$ROOT_DIR/scripts/init_db.sh"
"$ROOT_DIR/scripts/init_minio.sh"
"$ROOT_DIR/scripts/init_keycloak.sh"

echo "All infra initialized. You can now run the backend on host."
