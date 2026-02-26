# Tests

Questi test verificano gli endpoint del BFF.

## Prerequisiti
- Backend BFF avviato su `BASE_URL` (default: http://localhost:8000)
- Infra avviata con `./scripts/start_infra.sh`
- Bootstrap infra: `./scripts/init_all.sh`

## Auth
- Se `KEYCLOAK_ENABLED=false` nei .env: i test usano header `X-Debug-User`.
- Se `KEYCLOAK_ENABLED=true`: i test ottengono un token via password grant per l’utente creato dagli script.
