# OpenClaw BFF (Backend for Frontend)

Backend **FastAPI** che espone una API pubblica per frontend stile chat e, in parallelo, endpoint OpenAI-compatible.

Il servizio integra:
- **OpenClaw Gateway** via HTTP e WebSocket RPC
- **PostgreSQL** per persistenza conversazioni/messaggi/uploads
- **MinIO** per object storage
- **Keycloak** opzionale per autenticazione JWT

## Architettura in breve

- Le API BFF principali sono sotto ` /api/v1 `.
- Le API OpenAI-compatible sono sotto ` /v1/* ` più ` /tools/invoke `.
- Le conversazioni utente usano `conversation_id` (UUID pubblico) e mappano internamente a `openclaw_session_key`.
- Il flusso messaggi usa principalmente il loop **WS agent** (`agent`, `agent.wait`, subscribe eventi), con bridge SSE verso il frontend.

## API effettive

### 1) BFF API (`/api/v1`)

#### Health e gateway
- `GET /api/v1/health`
- `GET /api/v1/gateway/info`

#### Conversations
- `POST /api/v1/conversations`
- `GET /api/v1/conversations`
- `GET /api/v1/conversations/{conversation_id}`
- `PATCH /api/v1/conversations/{conversation_id}`
- `DELETE /api/v1/conversations/{conversation_id}` (soft delete)

#### Messages
- `GET /api/v1/conversations/{conversation_id}/messages?source=db|gateway`
- `POST /api/v1/conversations/{conversation_id}/messages` (non-stream)
- `POST /api/v1/conversations/{conversation_id}/messages/stream` (SSE)
- `POST /api/v1/conversations/{conversation_id}/abort`
- `POST /api/v1/conversations/{conversation_id}/inject`

#### Tools
- `GET /api/v1/tools/catalog`
- `POST /api/v1/conversations/{conversation_id}/tools/invoke`
- `POST /api/v1/conversations/{conversation_id}/tool-results`

#### Agents
- `GET /api/v1/agents`
- `POST /api/v1/agents`
- `GET /api/v1/agents/{agent_id}`
- `PATCH /api/v1/agents/{agent_id}`
- `DELETE /api/v1/agents/{agent_id}`

#### Agent Knowledge Files
- `GET /api/v1/agents/{agent_id}/knowledge/tree`
- `POST /api/v1/agents/{agent_id}/knowledge/folders`
- `PATCH /api/v1/agents/{agent_id}/knowledge/folders`
- `DELETE /api/v1/agents/{agent_id}/knowledge/folders`
- `POST /api/v1/agents/{agent_id}/knowledge/files/upload`
- `POST /api/v1/agents/{agent_id}/knowledge/files/base64`
- `PUT /api/v1/agents/{agent_id}/knowledge/files`
- `DELETE /api/v1/agents/{agent_id}/knowledge/files`
- `GET /api/v1/agents/{agent_id}/knowledge/files/content`
- `GET /api/v1/agents/{agent_id}/knowledge/files/download`
- `POST /api/v1/agents/{agent_id}/knowledge/reindex`

#### Uploads
- `POST /api/v1/uploads` (multipart upload diretto)
- `POST /api/v1/uploads/bytes`
- `POST /api/v1/uploads/base64`
- `POST /api/v1/uploads/presign` (compatibilità presigned flow)
- `GET /api/v1/uploads`
- `GET /api/v1/uploads/{upload_id}`
- `GET /api/v1/uploads/{upload_id}/links`
- `GET /api/v1/uploads/{upload_id}/download`
- `PATCH /api/v1/uploads/{upload_id}`
- `PUT /api/v1/uploads/{upload_id}/content`
- `PUT /api/v1/uploads/{upload_id}/content/base64`
- `DELETE /api/v1/uploads/{upload_id}`

### 2) OpenAI-compatible surface

- `GET /v1/models`
- `POST /v1/chat/completions`
- `POST /v1/responses`
- `POST /v1/completions` (legacy, tradotto internamente in chat completions)
- `POST /tools/invoke`

Nota: questa surface è un proxy autenticato verso OpenClaw; non usa il mapping conversazioni BFF come fanno gli endpoint `/api/v1/conversations/*`.

## Quick start (locale)

### Prerequisiti
- Docker + Docker Compose
- Python 3.12+
- OpenClaw Gateway attivo sull’host

### 1) Config

```bash
cp .env.example .env
```

Aggiorna almeno:
- `DATABASE_URL`
- `OPENCLAW_HTTP_BASE`
- `OPENCLAW_WS_URL`
- `OPENCLAW_BEARER_TOKEN` (se richiesto dal gateway)
- `OPENCLAW_IDENTITY_FILE` (consigliato, identity device del client OpenClaw)
- `OPENCLAW_STATE_DIR` (fallback per identity locale generata dal BFF)
- `KEYCLOAK_ENABLED`

### 2) Infra locale (Postgres/MinIO/Keycloak)

```bash
./scripts/init_all.sh
```

### 3) Avvio backend

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./scripts/dev_run.sh
```

Swagger:
- `http://127.0.0.1:8000/docs`

## Run via Docker

```bash
docker build -t openclaw-bff .
docker run --rm -p 8000:8000 --env-file .env openclaw-bff
```

## Auth model

- `KEYCLOAK_ENABLED=false`: no JWT verification, user derivato da `X-Debug-User` o `DEV_USER_ID`
- `KEYCLOAK_ENABLED=true`: JWT obbligatorio in `Authorization: Bearer <token>`

Per Keycloak mode sono rilevanti anche `KEYCLOAK_JWKS_URL`, `KEYCLOAK_ISSUER`, `KEYCLOAK_AUDIENCE`.

## Sicurezza e isolamento

- Ownership check lato DB per conversazioni e uploads sui percorsi `/api/v1/*`.
- `openclaw_session_key` è gestita dal backend per il routing OpenClaw; il forwarding raw da header client resta disabilitato di default (`ALLOW_RAW_OPENCLAW_SESSION_KEY=false`).
- Nota implementativa: `POST /api/v1/conversations/{conversation_id}/messages` include attualmente `openclaw_response.session_key` nel payload di risposta (campo diagnostico/compatibilità).
- Payload e schemi esposti dal BFF usano naming **snake_case** (`conversation_id`, `agent_id`, `client_message_id`, ...).
- Endpoint agenti (`/api/v1/agents/*`) leggono/modificano lo stato persistito in OpenClaw via WS RPC (nessun DB locale agenti nel BFF).
- In lista agenti, campi come `name/workspace/model` possono risultare `null` se non valorizzati o non restituiti dal gateway OpenClaw per quello specifico agente.
- Endpoint knowledge usano filesystem locale workspace agente (`<workspace>/memory/knowledge`) con path safety strict (niente traversal/assoluti/symlink escape) e non usano MinIO.

## Script utili

- `./scripts/start_infra.sh` – avvio container infra
- `./scripts/init_all.sh` – bootstrap completo infra
- `./scripts/dev_run.sh` – avvio backend con `.env`
- `./scripts/run_tests.sh` – avvio suite test
