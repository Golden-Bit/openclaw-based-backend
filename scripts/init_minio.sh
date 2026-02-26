#!/usr/bin/env bash
set -euo pipefail

# Idempotent MinIO bootstrap using minio/mc inside the compose network.
# Creates:
#  - bucket: openclaw-bff (or MINIO_BUCKET)
#  - user: openclaw-bff (or MINIO_BFF_ACCESS_KEY) with readwrite policy

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Compose name is fixed by docker-compose.infra.yml (top-level "name: openclaw-bff-infra")
NET="openclaw-bff-infra_default"

MINIO_ENDPOINT="http://minio:9000"
ROOT_USER="${MINIO_ROOT_USER:-minioadmin}"
ROOT_PASS="${MINIO_ROOT_PASSWORD:-minioadmin}"

BUCKET="${MINIO_BUCKET:-openclaw-bff}"

BFF_ACCESS="${MINIO_BFF_ACCESS_KEY:-openclaw-bff}"
BFF_SECRET="${MINIO_BFF_SECRET_KEY:-openclaw-bff-secret}"

echo "Initializing MinIO (bucket=$BUCKET user=$BFF_ACCESS)..."

docker run --rm --network "$NET" --entrypoint /bin/sh minio/mc:latest -c "
  set -e;
  mc alias set local $MINIO_ENDPOINT $ROOT_USER $ROOT_PASS >/dev/null;

  # Bucket
  mc mb --ignore-existing local/$BUCKET >/dev/null;

  # User (readwrite)
  (mc admin user info local $BFF_ACCESS >/dev/null 2>&1) || mc admin user add local $BFF_ACCESS $BFF_SECRET >/dev/null;
  mc admin policy attach local readwrite --user $BFF_ACCESS >/dev/null;

  echo 'MinIO ready.'
"

echo "MinIO initialized."
