#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# init_all.sh
# =============================================================================
# Avvia e inizializza TUTTA l'infrastruttura locale (docker) necessaria al BFF:
# - Postgres
# - MinIO
# - Keycloak
#
# NOTA: OpenClaw NON è nel compose e continua a girare su host separatamente.
#
# Questo script è idempotente:
# - docker compose up -d non duplica container
# - init_db/minio/keycloak creano risorse solo se mancano
# =============================================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Carica .env del repo (se presente) per prendere override di porte/credenziali.
# Uso set -a per esportare automaticamente le variabili.
if [[ -f "$ROOT_DIR/.env" ]]; then
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

"$ROOT_DIR/scripts/start_infra.sh"
"$ROOT_DIR/scripts/init_db.sh"
"$ROOT_DIR/scripts/init_minio.sh"
"$ROOT_DIR/scripts/init_keycloak.sh"

echo "All infra initialized. You can now run the backend on host."