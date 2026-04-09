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
- `OPENCLAW_DEFAULT_AGENT_ID`
- `AGENT_WORKSPACE_ROOT` (root namespace utenti per isolamento agenti/knowledge)
- `AGENT_NAMESPACE_SALT` (namespace utenti hash-only)
- `AGENT_NAMESPACE_ALLOW_LEGACY` (compatibilità con namespace legacy)
- `SHARED_FILES_ROOT` (directory file hosting pubblico)
- `SHARED_FILES_URL_PREFIX` (prefisso URL per download da browser)
- `BFF_PUBLIC_BASE_URL` (base URL assoluta usata nella skill share-files)
- `KEYCLOAK_ENABLED`
- `KEYCLOAK_PUBLIC_URL` (dominio pubblico Keycloak, anche https)
- `KEYCLOAK_INTERNAL_URL` (URL usato da script bootstrap)
- `KEYCLOAK_ISSUER`, `KEYCLOAK_JWKS_URL`, `KEYCLOAK_AUDIENCE`

Per Keycloak dietro reverse proxy:
- `KC_HOSTNAME` coerente con `KEYCLOAK_PUBLIC_URL`
- `KC_HTTP_ENABLED=true` se la TLS è terminata al proxy
- `KC_PROXY_HEADERS=xforwarded` (o `forwarded` in base al proxy)

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
- Agent knowledge tree: `http://localhost:8000/api/v1/agents/main/knowledge/tree`
- Shared hosted file (esempio): `http://localhost:8000/shared/files/public/example.txt`

Nota: alla creazione agente, il backend scrive automaticamente `skills/share-files/SKILL.md` nel workspace agente.

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
