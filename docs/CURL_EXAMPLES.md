# cURL examples

## Health
```bash
curl -s http://localhost:8000/api/v1/health | jq
```

## Create conversation
```bash
curl -s -X POST http://localhost:8000/api/v1/conversations \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"agentId":"main","title":"Demo"}' | jq
```

## List conversations
```bash
curl -s http://localhost:8000/api/v1/conversations \
  -H 'X-Debug-User: dev-user' | jq
```

## Stream message (SSE)
```bash
curl -N -X POST http://localhost:8000/api/v1/conversations/<id>/messages/stream \
  -H 'Accept: text/event-stream' \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"content":"ciao","clientMessageId":"m1"}'
```

## OpenAI-compat proxy (Chat Completions)
```bash
curl -N -X POST http://localhost:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{
    "model":"openclaw:main",
    "messages":[{"role":"user","content":"ciao"}],
    "stream": true,
    "user":"dev-user"
  }'
```
