# OpenClaw BFF – Architettura reale

## Obiettivo

OpenClaw BFF espone due superfici:

1. **BFF API (`/api/v1`)** per frontend applicativo (ownership e persistenza gestite dal backend)
2. **OpenAI-compatible API (`/v1/*` + `/tools/invoke`)** come proxy autenticato verso OpenClaw

Il backend comunica con OpenClaw via:
- **HTTP**: `/v1/responses`, `/v1/chat/completions`, `/tools/invoke`
- **WebSocket RPC**: `agent`, `agent.wait`, `chat.history`, `chat.abort`, `chat.inject`, `tools.catalog`, `agents.list`, `agent.identity.get`, `agents.files.list`, `agents.update`, `agents.delete`

## Componenti

- **FastAPI app** (`app/main.py`)
- **PostgreSQL** (conversations, messages, uploads, conversation_aliases)
- **MinIO** (file object storage)
- **Keycloak** opzionale (JWT + JWKS)
- **OpenClaw Gateway** esterno (host locale o remoto)

## Struttura moduli

- `app/api/v1/endpoints/*`: API BFF
- `app/api/openai_compat.py`: proxy OpenAI-compatible
- `app/core/openclaw_ws.py`: client WS RPC con handshake challenge + device signature
- `app/core/openclaw_http.py`: client HTTP con gestione errori upstream (`OpenClawHTTPError`)
- `app/core/security.py`: auth dependency (dev o JWT)
- `app/core/minio_client.py`: wrapper MinIO
- `app/db/models.py`: modelli SQLAlchemy
- `app/schemas/*`: contratti pydantic (snake_case)

## Lifecyle applicazione

In startup (`lifespan`):
1. Configura logging
2. Esegue `init_db(engine)` (`create_all`)
3. Inizializza MinIO e garantisce bucket
4. Non forza connect WS (client lazy)

In shutdown:
1. Chiusura WS client (best-effort)
2. `engine.dispose()`

## Modello dati

### Conversation
- `id` (UUID pubblico)
- `user_id`
- `agent_id`
- `openclaw_session_key` (interno)
- `is_deleted`, `created_at`, `updated_at`

### Message
- `conversation_id`
- `role` (`user|assistant|system|tool`)
- `content`, `raw`, `run_id`, `seq`, `created_at`

### Upload
- metadati file (`bucket`, `object_key`, `filename`, `mime_type`, `size_bytes`, `sha256`)
- `metadata_` (colonna DB `metadata`), `tags`, `status`, soft delete

### ConversationAlias
- presente a livello DB ma non usata nel routing dei path attivi `/api/v1/*`

## Flussi principali

### 1) Message non-stream
1. `POST /api/v1/conversations/{conversation_id}/messages`
2. ownership check conversazione
3. persist messaggio utente su DB
4. invoca WS `agent` + ascolta stream eventi (`agent`)
5. accumula testo assistant + tool events
6. persist risposta assistant su DB
7. restituisce `openclaw_response` con `run_id`, `agent_id`, `session_key`, `output_text`, `tool_events`

### 2) Message stream (SSE)
1. `POST /api/v1/conversations/{conversation_id}/messages/stream`
2. persist messaggio utente
3. WS `agent` + subscribe eventi
4. bridge verso SSE (`openclaw.agent`, `tool.event`, `message.delta`, `message.completed`)
5. persist assistant finale se `PERSIST_STREAMED_MESSAGES=true`

### 3) Abort/Inject
- `POST /api/v1/conversations/{conversation_id}/abort` -> WS `chat.abort`
- `POST /api/v1/conversations/{conversation_id}/inject` -> WS `chat.inject` + persist system message

### 4) Uploads
- Modalità diretta: multipart/bytes/base64
- Modalità compatibilità: presigned flow (`/uploads/presign`)
- CRUD completo con links, download stream, content replace, soft/hard delete

### 5) OpenAI-compatible
- `/v1/chat/completions` e `/v1/responses`: proxy HTTP/SSE verso OpenClaw
- `/v1/completions`: traduzione legacy -> chat completions
- `model` può selezionare agent (`openclaw:<agent>`)
- forwarding raw `x-openclaw-session-key` solo se `ALLOW_RAW_OPENCLAW_SESSION_KEY=true`

### 6) Agents management
- `GET /api/v1/agents` -> WS `agents.list`
- `GET /api/v1/agents/{agent_id}` -> `agents.list` + enrichment best-effort (`agent.identity.get`, opzionale `agents.files.list`)
- `PATCH /api/v1/agents/{agent_id}` -> WS `agents.update`
- `DELETE /api/v1/agents/{agent_id}` -> WS `agents.delete`

Nota: il BFF non persiste anagrafiche agenti su DB locale. Il source of truth resta OpenClaw.

## Sicurezza

- I path `/api/v1/*` applicano ownership su DB (`user_id`)
- `openclaw_session_key` non è l'id pubblico di conversazione (l'id pubblico resta `conversation_id`)
- il campo può comunque comparire nel payload di `send_message` (`openclaw_response.session_key`)
- In dev mode è disponibile `X-Debug-User`; in produzione va disabilitato (`KEYCLOAK_ENABLED=true`)

## Error handling

- Errori HTTP upstream OpenClaw mappati da `OpenClawHTTPError`
- Errori WS mappati in `HTTPException(502)` o evento SSE `error`
- Health endpoint espone diagnostica separata: `db_ok`, `openclaw_ws_ok`, `openclaw_ws_detail`
