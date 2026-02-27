from __future__ import annotations

"""OpenAI-compatible endpoints (proxy) for OpenClaw Gateway.

Questo router espone:
- /v1/responses (OpenAI Responses-like)
- /v1/chat/completions (OpenAI ChatCompletions-like)
- /v1/models

Modifica chiave (per la tua build OpenClaw):
- L'upstream OpenClaw *non* accetta l'input "structured" (array di messages + content blocks)
  con `model: openclaw:<agent>`; risponde 400 "input: Invalid input".
- Quindi qui normalizziamo sempre la richiesta verso l'upstream in modalità "simple":

    POST /v1/responses
      payload -> {"model":"openclaw", "input":"<prompt string>", "stream": true|false}
      headers -> x-openclaw-agent-id, x-openclaw-session-key (se presenti)

Note:
- La selezione del *modello reale* (OpenAI/Anthropic/...) NON avviene via `model` in questa API.
  Avviene dentro OpenClaw per l'agent selezionato (x-openclaw-agent-id).
"""

import json
import time
import uuid
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from app.core.config import settings
from app.core.openclaw_http import OpenClawHTTPError, post_json, stream_sse
from app.core.security import AuthenticatedUser, get_current_user
from app.db.session import get_db
from app.utils.openresponses import extract_output_text
from app.utils.sse import format_sse, iter_sse_events

router = APIRouter(tags=["openai"])


# =============================================================================
# Helpers: conversation + agent/session
# =============================================================================


def _safe_uuid(s: str) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(s)
    except Exception:
        return None


async def _get_conversation_or_none(db, user_id: str, conversation_id: Optional[uuid.UUID]):
    if not conversation_id:
        return None
    # Import locale per evitare cicli
    from sqlalchemy import select
    from app.db.models import Conversation

    return (
        await db.execute(
            select(Conversation).where(
                Conversation.id == conversation_id,
                Conversation.user_id == user_id,
                Conversation.is_deleted.is_(False),
            )
        )
    ).scalars().first()


def _infer_agent_from_payload(payload: dict) -> Optional[str]:
    """Se il client passa model='openclaw:<agent>', estraiamo <agent>."""

    model = payload.get("model")
    if isinstance(model, str) and model.startswith("openclaw:"):
        return model.split(":", 1)[1].strip() or None
    return None


def _resolve_agent_id(
    *,
    payload: dict,
    header_agent: Optional[str],
    conv_agent: Optional[str],
) -> str:
    # precedenza: header > model openclaw:<agent> > conversation > default
    if header_agent:
        return header_agent
    inferred = _infer_agent_from_payload(payload)
    if inferred:
        return inferred
    if conv_agent:
        return conv_agent
    return settings.openclaw_default_agent_id


def _resolve_session_key(
    *,
    header_session: Optional[str],
    conv_session: Optional[str],
    allow_raw: bool,
) -> Optional[str]:
    if allow_raw and header_session:
        return header_session
    if conv_session:
        return conv_session
    return None


# =============================================================================
# Helpers: input normalization (structured -> prompt string)
# =============================================================================


def _block_text(block: Any) -> str:
    """Estrae testo da un content block OpenAI/OpenResponses-like."""

    if isinstance(block, str):
        return block
    if not isinstance(block, dict):
        return ""
    t = block.get("type")
    if t in {"input_text", "output_text", "text"}:
        return str(block.get("text") or "")
    # immagini/file: rendiamoli leggibili come placeholder
    if t in {"input_image", "image_url"}:
        return f"[image] {block.get('image_url') or block.get('url') or ''}".strip()
    if t in {"input_file", "file_url"}:
        return f"[file] {block.get('file_url') or block.get('url') or ''}".strip()
    # fallback: prova campi comuni
    return str(block.get("text") or block.get("url") or "")


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [_block_text(b) for b in content]
        return "".join([p for p in parts if p])
    if isinstance(content, dict):
        # in alcuni payload content può essere {type,text}
        return _block_text(content)
    return ""


def _responses_input_to_prompt(inp: Any) -> str:
    """Normalizza payload['input'] (Responses) in stringa."""

    if isinstance(inp, str):
        return inp

    # OpenAI Responses può inviare input come array di message items
    if isinstance(inp, list):
        lines = []
        for item in inp:
            if not isinstance(item, dict):
                continue
            role = str(item.get("role") or "user")
            content = _content_to_text(item.get("content"))
            if content:
                lines.append(f"{role.upper()}: {content}")
        return "\n".join(lines)

    return ""


def _chat_messages_to_prompt(messages: Any) -> str:
    if not isinstance(messages, list):
        return ""
    lines = []
    for m in messages:
        if not isinstance(m, dict):
            continue
        role = str(m.get("role") or "user")
        content = _content_to_text(m.get("content"))
        if content:
            lines.append(f"{role.upper()}: {content}")
    return "\n".join(lines)


# =============================================================================
# /v1/responses
# =============================================================================


@router.post("/v1/responses", summary="OpenAI-compatible Responses")
async def openai_responses(
    request: Request,
    payload: dict = Body(...),
    user: AuthenticatedUser = Depends(get_current_user),
    x_bff_conversation_id: Optional[str] = Header(default=None),
    x_openclaw_agent_id: Optional[str] = Header(default=None),
    x_openclaw_session_key: Optional[str] = Header(default=None),
    db=Depends(get_db),
):
    """Proxy compatibile Responses.

    In upstream usiamo SEMPRE payload simple:
      {"model":"openclaw","input":"<prompt>","stream":bool}

    Per sessione/agent:
    - agent: header x-openclaw-agent-id > model openclaw:<agent> > conv.agent_id > default
    - session: se allow_raw_session_key=true, accetta header session key; altrimenti usa conv.openclaw_session_key
    """

    conv_id = _safe_uuid(x_bff_conversation_id) if x_bff_conversation_id else None
    conv = await _get_conversation_or_none(db, user.user_id, conv_id)

    agent_id = _resolve_agent_id(
        payload=payload,
        header_agent=x_openclaw_agent_id,
        conv_agent=(conv.agent_id if conv else None),
    )

    session_key = _resolve_session_key(
        header_session=x_openclaw_session_key,
        conv_session=(conv.openclaw_session_key if conv else None),
        allow_raw=settings.allow_raw_session_key,
    )

    # normalize input
    prompt = _responses_input_to_prompt(payload.get("input"))
    if not prompt:
        # Alcuni client mandano `messages` anche su /responses (best-effort)
        prompt = _chat_messages_to_prompt(payload.get("messages"))
    if not prompt:
        raise HTTPException(status_code=400, detail="Missing/invalid input")

    stream = bool(payload.get("stream"))

    upstream_payload = {"model": "openclaw", "input": prompt, "stream": stream}
    headers: Dict[str, str] = {"x-openclaw-agent-id": agent_id}
    if session_key:
        headers["x-openclaw-session-key"] = session_key

    try:
        if stream:
            return StreamingResponse(
                stream_sse("/v1/responses", upstream_payload, headers=headers),
                media_type="text/event-stream",
            )

        resp = await post_json("/v1/responses", upstream_payload, headers=headers)
        return JSONResponse(resp)

    except OpenClawHTTPError as e:
        raise HTTPException(
            status_code=502,
            detail={"upstream": "openclaw", "status": e.status_code, "url": e.url, "error": e.error},
        )


# =============================================================================
# /v1/chat/completions
# =============================================================================


@router.post("/v1/chat/completions", summary="OpenAI-compatible Chat Completions")
async def openai_chat_completions(
    request: Request,
    payload: dict = Body(...),
    user: AuthenticatedUser = Depends(get_current_user),
    x_bff_conversation_id: Optional[str] = Header(default=None),
    x_openclaw_agent_id: Optional[str] = Header(default=None),
    x_openclaw_session_key: Optional[str] = Header(default=None),
    db=Depends(get_db),
):
    """Proxy compatibile ChatCompletions.

    Strategia:
    - Convertiamo messages[] -> prompt string
    - Chiamiamo upstream /v1/responses in modalità simple
    - Convertiamo risposta in schema chat.completion (o chunk stream)

    Nota: il *modello* effettivo è deciso dall'agent in OpenClaw.
    """

    conv_id = _safe_uuid(x_bff_conversation_id) if x_bff_conversation_id else None
    conv = await _get_conversation_or_none(db, user.user_id, conv_id)

    agent_id = _resolve_agent_id(
        payload=payload,
        header_agent=x_openclaw_agent_id,
        conv_agent=(conv.agent_id if conv else None),
    )

    session_key = _resolve_session_key(
        header_session=x_openclaw_session_key,
        conv_session=(conv.openclaw_session_key if conv else None),
        allow_raw=settings.allow_raw_session_key,
    )

    prompt = _chat_messages_to_prompt(payload.get("messages"))
    if not prompt:
        raise HTTPException(status_code=400, detail="Missing/invalid messages")

    stream = bool(payload.get("stream"))

    upstream_payload = {"model": "openclaw", "input": prompt, "stream": stream}
    headers: Dict[str, str] = {"x-openclaw-agent-id": agent_id}
    if session_key:
        headers["x-openclaw-session-key"] = session_key

    chat_id = f"chatcmpl_{uuid.uuid4().hex}"
    created = int(time.time())

    try:
        if not stream:
            resp = await post_json("/v1/responses", upstream_payload, headers=headers)
            assistant_text = extract_output_text(resp)

            out = {
                "id": chat_id,
                "object": "chat.completion",
                "created": created,
                "model": payload.get("model") or "openclaw",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": assistant_text},
                        "finish_reason": "stop",
                    }
                ],
            }
            # usage best-effort
            usage = resp.get("usage") if isinstance(resp, dict) else None
            if isinstance(usage, dict):
                out["usage"] = {
                    "prompt_tokens": usage.get("input_tokens", 0),
                    "completion_tokens": usage.get("output_tokens", 0),
                    "total_tokens": usage.get("total_tokens", 0),
                }
            return JSONResponse(out)

        # streaming: translate response.output_text.delta -> chat.completion.chunk
        async def gen() -> AsyncGenerator[bytes, None]:
            byte_stream = stream_sse("/v1/responses", upstream_payload, headers=headers)
            async for ev in iter_sse_events(byte_stream):
                # OpenResponses delta events
                if ev.event.endswith("output_text.delta") or ev.event.endswith("response.output_text.delta"):
                    try:
                        j = json.loads(ev.data)
                        delta = j.get("delta") or j.get("text") or ""
                    except Exception:
                        delta = ""
                    if not delta:
                        continue
                    chunk = {
                        "id": chat_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": payload.get("model") or "openclaw",
                        "choices": [{"index": 0, "delta": {"content": delta}, "finish_reason": None}],
                    }
                    yield b"data: " + json.dumps(chunk).encode("utf-8") + b"\n\n"
                    continue

                if ev.event.endswith("completed") or ev.event.endswith("response.completed"):
                    chunk = {
                        "id": chat_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": payload.get("model") or "openclaw",
                        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                    }
                    yield b"data: " + json.dumps(chunk).encode("utf-8") + b"\n\n"
                    yield b"data: [DONE]\n\n"
                    return

                # se l'upstream manda [DONE] come message
                if ev.data.strip() == "[DONE]":
                    yield b"data: [DONE]\n\n"
                    return

        return StreamingResponse(gen(), media_type="text/event-stream")

    except OpenClawHTTPError as e:
        raise HTTPException(
            status_code=502,
            detail={"upstream": "openclaw", "status": e.status_code, "url": e.url, "error": e.error},
        )


# =============================================================================
# /v1/models
# =============================================================================


@router.get("/v1/models", summary="List models (compat)")
async def openai_models(_: AuthenticatedUser = Depends(get_current_user)):
    """Ritorna una lista minima. Il routing vero è dentro OpenClaw agent."""

    # Se vuoi, qui puoi interrogare OpenClaw, ma per ora teniamo statico
    return {
        "object": "list",
        "data": [
            {"id": "openclaw", "object": "model", "owned_by": "openclaw"},
        ],
    }
