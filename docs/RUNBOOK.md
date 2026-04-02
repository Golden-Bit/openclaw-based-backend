# Runbook – avvio completo locale

## 0) Prerequisiti

- Docker + Docker Compose
- Python 3.12+
- OpenClaw Gateway attivo (host locale o endpoint raggiungibile)

## 1) Configurazione

```bash
cp .env.example .env
```

Verifica almeno:
- `DATABASE_URL`
- `OPENCLAW_HTTP_BASE`
- `OPENCLAW_WS_URL`
- `OPENCLAW_BEARER_TOKEN` (se richiesto)
- `OPENCLAW_IDENTITY_FILE` (consigliato: identity del client OpenClaw esistente)
- `OPENCLAW_STATE_DIR` (fallback per identity locale generata)
- `KEYCLOAK_ENABLED`

## 2) Avvio infrastruttura

```bash
./scripts/start_infra.sh
```

Servizi avviati:
- Postgres (`localhost:5432`)
- MinIO (`localhost:9000`, console `localhost:9001`)
- Keycloak (`localhost:8080`)

## 3) Bootstrap risorse

```bash
./scripts/init_all.sh
```

Effetti principali:
- Postgres: role+db applicativi
- MinIO: bucket e utente applicativo
- Keycloak: realm/client/user di test

## 4) Avvio backend (host)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./scripts/dev_run.sh
```

Endpoint utili:
- Swagger: `http://localhost:8000/docs`
- Health: `http://localhost:8000/api/v1/health`
- Gateway info: `http://localhost:8000/api/v1/gateway/info`
- Agents list: `http://localhost:8000/api/v1/agents`

## 5) Test

```bash
./scripts/run_tests.sh
```

Nota operativa:
- parte della suite include test legacy/non allineati o test OpenClaw-dependent marcati skip.
- usa i test come smoke/regressione parziale, non come copertura completa del comportamento corrente.

## 6) Avvio container applicativo (alternativo)

```bash
docker build -t openclaw-bff .
docker run --rm -p 8000:8000 --env-file .env openclaw-bff
```
