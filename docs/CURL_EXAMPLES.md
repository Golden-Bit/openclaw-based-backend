# cURL examples (contratto attuale)

> Esempi in modalità DEV (`KEYCLOAK_ENABLED=false`) con header `X-Debug-User`.

## Health

```bash
curl -s http://localhost:8000/api/v1/health \
  -H 'X-Debug-User: dev-user' | jq
```

## Gateway info

```bash
curl -s http://localhost:8000/api/v1/gateway/info \
  -H 'X-Debug-User: dev-user' | jq
```

## Create conversation

```bash
curl -s -X POST http://localhost:8000/api/v1/conversations \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"agent_id":"main","title":"Demo"}' | jq
```

## List conversations

```bash
curl -s http://localhost:8000/api/v1/conversations \
  -H 'X-Debug-User: dev-user' | jq
```

## Send message (non-stream)

```bash
curl -s -X POST http://localhost:8000/api/v1/conversations/<conversation_id>/messages \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"content":"ciao","client_message_id":"m1"}' | jq
```

## Stream message (SSE)

```bash
curl -N -X POST http://localhost:8000/api/v1/conversations/<conversation_id>/messages/stream \
  -H 'Accept: text/event-stream' \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"content":"ciao","client_message_id":"m1"}'
```

## Abort run

```bash
curl -s -X POST http://localhost:8000/api/v1/conversations/<conversation_id>/abort \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"run_id":null}' | jq
```

## Tools catalog

```bash
curl -s http://localhost:8000/api/v1/tools/catalog \
  -H 'X-Debug-User: dev-user' | jq
```

## List agents

```bash
curl -s http://localhost:8000/api/v1/agents \
  -H 'X-Debug-User: dev-user' | jq
```

## Create agent

> Nota: `workspace` deve essere relativo; il backend lo normalizza automaticamente sotto il namespace workspace dell'utente.

```bash
curl -s -X POST http://localhost:8000/api/v1/agents \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"name":"Support Agent","workspace":"support-agent","emoji":"🤖"}' | jq
```

## Agent detail

```bash
curl -s "http://localhost:8000/api/v1/agents/main?include_files=true" \
  -H 'X-Debug-User: dev-user' | jq
```

## Update agent

```bash
curl -s -X PATCH http://localhost:8000/api/v1/agents/main \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"name":"Main Agent","model":"openai:gpt-4.1"}' | jq
```

## Delete agent

```bash
curl -s -X DELETE "http://localhost:8000/api/v1/agents/main?delete_files=true" \
  -H 'X-Debug-User: dev-user' | jq
```

## Agent knowledge tree

```bash
curl -s "http://localhost:8000/api/v1/agents/main/knowledge/tree?path=" \
  -H 'X-Debug-User: dev-user' | jq
```

## Create knowledge folder

```bash
curl -s -X POST "http://localhost:8000/api/v1/agents/main/knowledge/folders" \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"path":"project-a/docs"}' | jq
```

## Upload knowledge file (multipart)

Markdown uploads stay single-file only when the target path is standalone. Non-Markdown uploads (`.txt`, `.json`, `.csv`, `.pdf`, `.docx`, `.xlsx`, `.pptx`) are stored as the original file plus a generated sibling `<stem>.md` in the same folder. If the original file already exists, the usual `overwrite=true` or `upsert=true` controls still apply; if only `<stem>.md` already exists, the backend preserves that user-authored markdown and allocates the first free incremented basename for the new managed pair. Direct upload/replace to a managed generated `<stem>.md` path returns `409`, including when the original already exists and the markdown sibling path is still reserved but missing. Deleting either member of a managed pair removes both files; deleting a standalone markdown file removes only that file.

```bash
curl -s -X POST "http://localhost:8000/api/v1/agents/main/knowledge/files/upload" \
  -H 'X-Debug-User: dev-user' \
  -F "path=project-a/docs" \
  -F "overwrite=true" \
  -F "file=@./README.md" | jq
```

## Upload knowledge file (base64)

```bash
curl -s -X POST "http://localhost:8000/api/v1/agents/main/knowledge/files/base64" \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"path":"project-a/docs","filename":"note.md","content_base64":"IyBIZWxsbwo=","overwrite":true}' | jq
```

Example non-Markdown upload that stores both `brief.pdf` and generated `brief.md`:

```bash
curl -s -X POST "http://localhost:8000/api/v1/agents/main/knowledge/files/base64" \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"path":"project-a/docs","filename":"brief.pdf","content_base64":"JVBERi0xLjQK","overwrite":true}' | jq
```

## Upload knowledge file in background (multipart)

```bash
curl -s -X POST "http://localhost:8000/api/v1/agents/main/knowledge/files/upload/background" \
  -H 'X-Debug-User: dev-user' \
  -F "path=project-a/docs" \
  -F "overwrite=true" \
  -F "file=@./README.md" | jq
```

## Upload knowledge file in background (base64)

```bash
curl -s -X POST "http://localhost:8000/api/v1/agents/main/knowledge/files/base64/background" \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"path":"project-a/docs","filename":"brief.pdf","content_base64":"JVBERi0xLjQK","overwrite":true}' | jq
```

## Replace knowledge file in background

```bash
curl -s -X PUT "http://localhost:8000/api/v1/agents/main/knowledge/files/background" \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"path":"project-a/docs/brief.pdf","content_base64":"JVBERi0xLjQK","upsert":true}' | jq
```

## List pending background knowledge tasks

```bash
curl -s "http://localhost:8000/api/v1/agents/main/knowledge/tasks/pending" \
  -H 'X-Debug-User: dev-user' | jq
```

## Get background knowledge task status

```bash
curl -s "http://localhost:8000/api/v1/agents/main/knowledge/tasks/<task_id>" \
  -H 'X-Debug-User: dev-user' | jq
```

## Read knowledge file metadata with associated task info

The response keeps file metadata path-based and adds `task_info` with:
- `association_status`: `direct`, `managed_original`, or `ambiguous`
- `canonical_path`: the task path used for association
- `active_task`: newest matching `pending`/`running` task, when present
- `latest_successful_task`: newest matching succeeded task, matched by final stored `result.path`

If you ask for a managed markdown file such as `project-a/docs/brief.md`, the file metadata still refers to `brief.md`, while `task_info.canonical_path` points to the paired original file path `project-a/docs/brief.pdf`.

```bash
curl -s "http://localhost:8000/api/v1/agents/main/knowledge/files/info?path=project-a/docs/brief.pdf" \
  -H 'X-Debug-User: dev-user' | jq
```

## Read knowledge file content

```bash
curl -s "http://localhost:8000/api/v1/agents/main/knowledge/files/content?path=project-a/docs/note.md" \
  -H 'X-Debug-User: dev-user' | jq
```

## Download knowledge file

```bash
curl -L "http://localhost:8000/api/v1/agents/main/knowledge/files/download?path=project-a/docs/note.md" \
  -H 'X-Debug-User: dev-user' \
  -o ./note.md
```

## Replace knowledge file content (PUT)

`PUT` on `note.md` works when that markdown file is standalone. If the same path is the generated sibling of `note.txt`, `note.pdf`, `note.docx`, `note.xlsx`, `note.pptx`, `note.json`, or `note.csv`, the endpoint returns `409` and leaves the managed pair unchanged.

```bash
curl -s -X PUT "http://localhost:8000/api/v1/agents/main/knowledge/files" \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"path":"project-a/docs/note.md","content_base64":"IyBVcGRhdGVkCg==","upsert":true}' | jq
```

## Delete knowledge file

Deleting `project-a/docs/brief.pdf` removes both `brief.pdf` and its managed generated `brief.md`. Deleting `project-a/docs/brief.md` does the same when that markdown file belongs to a managed pair. Deleting standalone `project-a/docs/note.md` removes only `note.md`.

```bash
curl -s -X DELETE "http://localhost:8000/api/v1/agents/main/knowledge/files?path=project-a/docs/note.md" \
  -H 'X-Debug-User: dev-user' | jq
```

## Download hosted shared file (default behavior)

```bash
curl -L "http://localhost:8000/shared/files/public/example.txt" \
  -o ./example.txt
```

## Preview hosted shared file inline

```bash
curl -L "http://localhost:8000/shared/files/public/example.txt?inline=true" \
  -o ./example.txt
```

## Invoke tool in conversation

```bash
curl -s -X POST http://localhost:8000/api/v1/conversations/<conversation_id>/tools/invoke \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"tool":"bash","action":null,"args":{"command":"pwd"}}' | jq
```

## Upload diretto multipart

```bash
curl -s -X POST http://localhost:8000/api/v1/uploads \
  -H 'X-Debug-User: dev-user' \
  -F 'file=@./README.md' \
  -F 'include_presigned_get=true' | jq
```

## Presign compat flow

```bash
curl -s -X POST http://localhost:8000/api/v1/uploads/presign \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{"filename":"doc.txt","mime_type":"text/plain","size_bytes":12}' | jq
```

## OpenAI-compatible chat completions (stream)

```bash
curl -N -X POST http://localhost:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{
    "model":"openclaw:main",
    "messages":[{"role":"user","content":"ciao"}],
    "stream": true
  }'
```

## OpenAI-compatible responses (non-stream)

```bash
curl -s -X POST http://localhost:8000/v1/responses \
  -H 'Content-Type: application/json' \
  -H 'X-Debug-User: dev-user' \
  -d '{
    "model":"openclaw:main",
    "input":"Ciao, fammi un riepilogo",
    "stream": false
  }' | jq
```
