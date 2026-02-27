#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# dev_run.sh
# =============================================================================
# Avvia il backend FastAPI (BFF) sul tuo HOST (non dentro Docker),
# leggendo la configurazione dal file .env nella root del repo.
#
# Prerequisiti:
# - python + venv attivo
# - dipendenze installate: pip install -r requirements.txt
# - infra avviata: ./scripts/init_all.sh
#
# Nota:
# - KEYCLOAK_ENABLED=true richiede Authorization: Bearer <JWT Keycloak> per chiamare API.
# - KEYCLOAK_ENABLED=false abilita header X-Debug-User per test rapidi.
# =============================================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f ".env" ]]; then
  echo "Missing .env in repo root. Copy .env.example -> .env and edit." >&2
  exit 1
fi

# Carica variabili da .env in modo robusto.
# set -a esporta automaticamente tutte le variabili definite in .env
set -a
source .env
set +a

# Avvio backend (no reload per evitare problemi con cartelle infra/* e permessi Docker)
uvicorn app.main:app --host 0.0.0.0 --port "${BFF_PORT:-8000}"