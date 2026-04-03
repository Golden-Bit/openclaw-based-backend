#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Load .env when script is invoked directly.
if [[ -f "$ROOT_DIR/.env" ]]; then
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

# Keep KC_* aligned with new public URL model when explicit overrides are absent.
if [[ -z "${KC_HOSTNAME:-}" ]]; then
  export KC_HOSTNAME="${KEYCLOAK_PUBLIC_URL:-http://localhost:8080}"
fi
if [[ -z "${KEYCLOAK_INTERNAL_URL:-}" ]]; then
  export KEYCLOAK_INTERNAL_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
fi

echo "[1/2] Starting infra (Postgres, MinIO, Keycloak)..."
docker compose -f docker-compose.infra.yml up -d

echo "[2/2] Waiting for services..."
KC_INTERNAL="${KEYCLOAK_INTERNAL_URL:-${KEYCLOAK_BASE_URL:-http://localhost:8080}}"
"$ROOT_DIR/scripts/wait_for_http.sh" "$KC_INTERNAL/realms/master" 120
"$ROOT_DIR/scripts/wait_for_http.sh" "http://localhost:9000/minio/health/ready" 120

# Postgres healthcheck is inside container; we just wait a bit.
sleep 2
echo "Infra is up."
