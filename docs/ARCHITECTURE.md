# OpenClaw BFF – Architettura (FastAPI)

## Obiettivo
Un **Backend-For-Frontend (BFF)** che espone una REST API pubblica per un frontend stile ChatGPT,
mentre comunica con **OpenClaw** (in locale) tramite:
- **HTTP** (`/v1/responses`, `/v1/chat/completions`, `/tools/invoke`)
- **WebSocket RPC** (metodi `chat.*`, `sessions.*`, `tools.catalog`, ...)

## Componenti
- **openclaw-bff (FastAPI)**: API pubblica
- **Postgres**: persistenza conversazioni, mapping conversationId → sessionKey, messaggi (cache), uploads metadata
- **MinIO**: object storage per upload (presigned PUT/GET)
- **Keycloak**: autenticazione OAuth2/OpenID Connect (JWT), **disattivabile** via env

## Flussi principali
### Chat streaming
FE → `POST /api/v1/conversations/{id}/messages/stream` (SSE)
BFF → OpenClaw `POST /v1/responses stream:true` (SSE) → proxy SSE verso FE

### Abort
FE → `POST /api/v1/conversations/{id}/abort`
BFF → OpenClaw WS `chat.abort { sessionKey }`

### Upload
FE → `POST /api/v1/uploads` → presigned PUT
FE carica su MinIO → poi invia URL come attachment nel messaggio.

## Sicurezza (IDOR)
Non esporre mai direttamente `x-openclaw-session-key` al FE.
Il FE usa `conversationId` e il BFF fa ownership-check su DB.
