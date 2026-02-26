# OpenClaw BFF (Backend for Frontend)

Backend **FastAPI** che espone una **Public REST API** per un frontend stile ChatGPT, mentre comunica con **OpenClaw Gateway** in locale tramite:

- **HTTP**: OpenResponses (`/v1/responses`), OpenAI Chat Completions (`/v1/chat/completions`), Tools Invoke (`/tools/invoke`)
- **WebSocket**: metodi RPC (`chat.history`, `chat.abort`, `chat.inject`, `sessions.list`, `tools.catalog`, ecc.)

Inoltre integra:

- **PostgreSQL** per persistenza conversazioni/messaggi/mapping sessioni
- **MinIO** per upload file (presigned URL)
- **Keycloak** (opzionale) per autenticazione JWT, disattivabile via ENV.

## Quick start (locale)

1) Crea DB `openclaw_bff` in Postgres e assicurati che Postgres sia in esecuzione.
2) Avvia MinIO in locale e crea (o lascia creare) il bucket `openclaw-bff`.
3) Avvia OpenClaw Gateway in locale e annota:
   - base HTTP (es. `http://127.0.0.1:3434`)
   - WS URL (es. `ws://127.0.0.1:3434/ws`)
   - token (se richiesto dal tuo gateway)

### Run con venv

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Config
cp .env.example .env
# modifica .env se necessario

uvicorn app.main:app --reload --port 8000
```

Apri Swagger:
- `http://127.0.0.1:8000/docs`

## Run via Docker

```bash
docker build -t openclaw-bff .
docker run --rm -p 8000:8000 --env-file .env openclaw-bff
```

## Autenticazione (Keycloak)

- Se `KEYCLOAK_ENABLED=false` il backend non verifica JWT e usa `DEV_USER_ID` come utente.
- Se `KEYCLOAK_ENABLED=true`, serve un JWT in `Authorization: Bearer <token>`.

> Nota: In produzione **non** bypassare l’auth.

## Endpoint principali

La API pubblica BFF è sotto `/api/v1`.

- Conversazioni: `/api/v1/conversations`
- Messaggi: `/api/v1/conversations/{conversationId}/messages` (+ `/stream`)
- Abort: `/api/v1/conversations/{conversationId}/abort`
- Inject: `/api/v1/conversations/{conversationId}/inject`
- Upload: `/api/v1/uploads`
- Tools: `/api/v1/tools/catalog`, `/api/v1/conversations/{id}/tools/invoke`

### OpenAI-compat (per OpenWebUI & integrazioni)

Il backend espone anche endpoint compatibili OpenAI:

- `POST /v1/responses`
- `POST /v1/chat/completions`
- `POST /tools/invoke`
- `GET /v1/models`

Questi endpoint **passano sempre dal BFF** e applicano ownership/isolamento sessioni.

## Note di sicurezza

- Il BFF non espone `openclawSessionKey` al FE.
- Il FE usa `conversationId`; il BFF mappa su `openclawSessionKey` interno.
- Per compat OpenAI, il campo `user` (o header `x-bff-conversation-id`) viene usato per il routing.

