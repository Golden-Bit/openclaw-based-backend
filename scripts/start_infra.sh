#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/2] Starting infra (Postgres, MinIO, Keycloak)..."
docker compose -f docker-compose.infra.yml up -d

echo "[2/2] Waiting for services..."
"$ROOT_DIR/scripts/wait_for_http.sh" "http://localhost:8080/realms/master" 120
"$ROOT_DIR/scripts/wait_for_http.sh" "http://localhost:9000/minio/health/ready" 120

# Postgres healthcheck is inside container; we just wait a bit.
sleep 2
echo "Infra is up."
