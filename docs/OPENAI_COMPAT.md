# OpenAI-compatible endpoints

Il backend espone una superficie compatibile OpenAI per integrazioni (es. OpenWebUI, toolchain custom):

- `GET /v1/models`
- `POST /v1/chat/completions`
- `POST /v1/responses`
- `POST /v1/completions` (legacy)
- `POST /tools/invoke`

## Comportamento reale

Questi endpoint sono implementati in `app/api/openai_compat.py` e funzionano come **proxy autenticato verso OpenClaw**.

Punti chiave:
- supportano `stream=true` via SSE dove previsto
- passano header agent/session verso OpenClaw secondo policy locale
- non usano il routing conversazioni `/api/v1/conversations/*`

## Agent selection

Puoi selezionare l’agent in due modi:

1. Header `x-openclaw-agent-id`
2. Campo `model` in forma:
   - `openclaw:<agentId>`
   - `agent:<agentId>`

Se non fornito, viene usato `OPENCLAW_DEFAULT_AGENT_ID`.

## Session forwarding

Header `x-openclaw-session-key` viene forwardato **solo** se:

`ALLOW_RAW_OPENCLAW_SESSION_KEY=true`

Default consigliato: `false`.

## /v1/completions

`/v1/completions` è mantenuto per compatibilità e viene tradotto internamente in richiesta chat completions.

## /v1/models

Ritorna una lista minima adatta a client OpenAI-like:
- `openclaw`
- `openclaw:<default_agent>`

## Autenticazione

Le stesse regole del resto del backend:
- dev mode (`KEYCLOAK_ENABLED=false`): `X-Debug-User` / `DEV_USER_ID`
- keycloak mode (`KEYCLOAK_ENABLED=true`): `Authorization: Bearer <JWT>`

## Nota importante

I documenti legacy che menzionano `x-bff-conversation-id` o alias conversation routing non descrivono più il comportamento attivo dell’implementazione corrente di `openai_compat.py`.
