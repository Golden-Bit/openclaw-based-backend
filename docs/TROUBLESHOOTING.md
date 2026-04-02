# Troubleshooting

## 401 / 403 su endpoint API

### Causa comune
- `KEYCLOAK_ENABLED=true` ma token mancante/non valido

### Verifica
- `Authorization: Bearer <token>` presente
- `KEYCLOAK_JWKS_URL` raggiungibile
- `KEYCLOAK_ISSUER` e `KEYCLOAK_AUDIENCE` coerenti col realm/client

### Fix
- in locale rapido: imposta `KEYCLOAK_ENABLED=false` e usa `X-Debug-User`

---

## Health ok=false con db_ok=false

### Causa
- connessione DB errata o ruolo/db non inizializzati

### Verifica/Fix
- controlla `DATABASE_URL`
- esegui `./scripts/init_db.sh` (o `./scripts/init_all.sh`)

---

## Health ok=false con openclaw_ws_ok=false

### Causa
- OpenClaw WS non raggiungibile
- handshake challenge/signature fallita

### Verifica
- `OPENCLAW_WS_URL` corretto
- `OPENCLAW_BEARER_TOKEN` valido (se richiesto)
- `OPENCLAW_IDENTITY_FILE` esistente e leggibile

### Debug utile
- `OPENCLAW_WS_DEBUG=1`
- `OPENCLAW_WS_DEBUG_PAYLOAD=1`
- `OPENCLAW_WS_DEBUG_EVENTS=chat,agent`

---

## 502 su /v1/* o /tools/invoke

### Causa
- errore upstream OpenClaw

### Verifica/Fix
- controlla `OPENCLAW_HTTP_BASE`
- verifica policy/permessi agent e tool lato gateway
- leggi `detail` restituito dal BFF (mappa `OpenClawHTTPError`)

---

## 503 su `/api/v1/agents/{agent_id}` in PATCH/DELETE

### Causa
- scope WS insufficienti verso OpenClaw (`operator.admin` richiesto da gateway)

### Verifica/Fix
- controlla `OPENCLAW_SCOPES` lato BFF/gateway token
- verifica che il token usato dal gateway includa scope admin necessari
- prova `GET /api/v1/agents` (read scope) per distinguere problema auth da raggiungibilità

---

## MinIO error: "path in endpoint is not allowed"

### Causa
- endpoint MinIO configurato con schema/path

### Fix
- usa `MINIO_ENDPOINT=host:port` (es. `localhost:9000`)
- non usare `http://` in `MINIO_ENDPOINT`

---

## Upload fallisce con 413

### Causa
- file oltre soglia `UPLOAD_MAX_BYTES`

### Fix
- riduci dimensione file o aumenta `UPLOAD_MAX_BYTES`

---

## Test che falliscono con campi/shape inattesi

### Causa
- alcuni test/documenti legacy usano contratti camelCase o shape vecchi

### Stato attuale
- API BFF espone prevalentemente payload snake_case (`conversation_id`, `agent_id`, `client_message_id`, ...)
- endpoint upload principale (`POST /api/v1/uploads`) è upload diretto multipart, non presign-only

---

## `/api/v1/agents` restituisce `name/workspace/model = null`

### Causa
- il gateway OpenClaw può restituire agent summary parziali (es. solo `id`)
- campi opzionali non valorizzati lato agente risultano `null` nel payload BFF

### Verifica/Fix
- controlla `GET /api/v1/agents/{agent_id}` per enrichment (`identity` e opzionalmente `files`)
- se necessario aggiorna l'agente via `PATCH /api/v1/agents/{agent_id}` per valorizzare `name/workspace/model`

---

## Errori `400` su knowledge path (`/api/v1/agents/{agent_id}/knowledge/*`)

### Causa
- path non valida (assoluta, `..`, home-relative, escape root)

### Verifica/Fix
- usa sempre path **relative** alla root knowledge (`<workspace>/memory/knowledge`)
- evita prefissi `/`, `~`, e segmenti `..`

---

## `409` su upload/replace knowledge file

### Causa
- path destinazione già occupato da cartella
- file esistente con `overwrite=false`
- `PUT /files` su file mancante con `upsert=false`

### Verifica/Fix
- abilita `overwrite=true` per endpoint upload
- usa `upsert=true` su `PUT /files` quando vuoi creare se assente
