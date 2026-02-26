#!/usr/bin/env bash
set -euo pipefail

# Idempotent DB bootstrap inside the postgres container.
# Creates:
#  - role: openclaw_bff
#  - database: openclaw_bff
#  - extension: pgcrypto
#
# Uses superuser from docker-compose env defaults.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

POSTGRES_SVC="postgres"
SU_USER="${POSTGRES_SUPERUSER:-postgres}"
SU_DB="${POSTGRES_SUPERDB:-postgres}"

BFF_DB="${BFF_DB_NAME:-openclaw_bff}"
BFF_USER="${BFF_DB_USER:-openclaw_bff}"
BFF_PASS="${BFF_DB_PASSWORD:-openclaw_bff}"

echo "Initializing Postgres (db=$BFF_DB user=$BFF_USER)..."

docker compose -f docker-compose.infra.yml exec -T "$POSTGRES_SVC" psql -U "$SU_USER" -d "$SU_DB" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${BFF_USER}') THEN
    CREATE ROLE ${BFF_USER} LOGIN PASSWORD '${BFF_PASS}';
  END IF;
END
\$\$;

DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_database WHERE datname = '${BFF_DB}') THEN
    CREATE DATABASE ${BFF_DB} OWNER ${BFF_USER};
  END IF;
END
\$\$;
SQL

docker compose -f docker-compose.infra.yml exec -T "$POSTGRES_SVC" psql -U "$SU_USER" -d "$BFF_DB" <<SQL
CREATE EXTENSION IF NOT EXISTS pgcrypto;
GRANT ALL PRIVILEGES ON DATABASE ${BFF_DB} TO ${BFF_USER};
SQL

echo "Postgres initialized."
