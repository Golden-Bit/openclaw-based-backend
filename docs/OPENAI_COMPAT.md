# OpenAI-compatible endpoints

Il BFF espone endpoint compatibili OpenAI per integrazioni tipo OpenWebUI:

- `GET /v1/models`
- `POST /v1/responses`
- `POST /v1/chat/completions`
- `POST /tools/invoke`

## Routing conversazione
Il client può fornire:
- `user` nel payload (OpenAI/OpenResponses) → il BFF lo mappa in conversation/session per quell’utente
- oppure `x-bff-conversation-id` (header)

Il BFF NON deve permettere al client di impostare direttamente `x-openclaw-session-key`.
