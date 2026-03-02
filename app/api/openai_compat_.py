from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from starlette.responses import JSONResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.openclaw_http import post_json, stream_sse
from app.core.security import AuthenticatedUser, get_current_user
from app.db.models import Conversation
from app.db.session import get_db
from app.utils.openresponses import extract_output_text
from app.utils.sse import iter_sse_events

router = APIRouter()


# =============================================================================
# DB helpers
# =============================================================================

async def _get_conversation_by_id(db: AsyncSession, user_id: str, conversation_id: str) -> Conversation:
    try:
        cid = uuid.UUID(conversation_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid x-bff-conversation-id")

    conv = (
        await db.execute(
            select(Conversation).where(
                Conversation.id == cid,
                Conversation.user_id == user_id,
                Conversation.is_deleted.is_(False),
            )
        )
    ).scalars().first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conv


async def _get_or_create_conversation_by_alias(db: AsyncSession, user_id: str, alias: str) -> Conversation:
    conv = (
        await db.execute(
            select(Conversation).where(
                Conversation.user_id == user_id,
                Conversation.alias == alias,
                Conversation.is_deleted.is_(False),
            )
        )
    ).scalars().first()
    if conv:
        return conv

    conv = Conversation(user_id=user_id, alias=alias, agent_id=settings.openclaw_default_agent_id)
    conv.openclaw_session_key = f"bff:{uuid.uuid4()}"
    db.add(conv)
    await db.commit()
    await db.refresh(conv)
    return conv


# =============================================================================
# Helpers: infer agent/session from request
# =============================================================================

def _infer_agent_from_payload(payload: dict) -> Optional[str]:
    """
    Interpreta `model` per selezionare agentId:
    - "openclaw:<agent>"  -> agent = <agent>
    - "openclaw"          -> None (usa default agent della conversazione)
    - altro               -> None (NON lo trattiamo come agentId)
    """
    model = str(payload.get("model") or "").strip()
    if model.startswith("openclaw:"):
        return model.split(":", 1)[1].strip() or None
    return None


def _infer_alias_from_payload(payload: dict) -> str:
    """
    Alias conversazione (best-effort):
    - payload.user
    - payload.metadata.user_id / userId / user
    - fallback "default"
    """
    u = payload.get("user")
    if isinstance(u, str) and u.strip():
        return u.strip()
    md = payload.get("metadata")
    if isinstance(md, dict):
        u2 = md.get("user") or md.get("user_id") or md.get("userId")
        if isinstance(u2, str) and u2.strip():
            return u2.strip()
    return "default"


def _headers_for_conv(
    conv: Conversation,
    *,
    agent_override: Optional[str] = None,
    agent_header_override: Optional[str] = None,
    session_override: Optional[str] = None,
) -> Dict[str, str]:
    agent_id = (
        (agent_header_override or "").strip()
        or (agent_override or "").strip()
        or (conv.agent_id or "").strip()
        or settings.openclaw_default_agent_id
    )

    h: Dict[str, str] = {"x-openclaw-agent-id": agent_id}

    sk = (session_override or "").strip() or (conv.openclaw_session_key or "").strip()
    if sk:
        h["x-openclaw-session-key"] = sk
    return h


# =============================================================================
# Helpers: convert OpenAI-like payloads to OpenClaw simple payload
# =============================================================================

_Content = Union[str, List[Any], Dict[str, Any]]


def _extract_text_from_content(content: _Content) -> str:
    """
    Estrae testo da:
    - string
    - list di parts {type: input_text/text/output_text, text: "..."}
    - dict singolo (rare)
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        t = content.get("type")
        if t in {"input_text", "text", "output_text"}:
            return str(content.get("text") or "")
        return str(content.get("text") or content.get("content") or "")
    if isinstance(content, list):
        parts: List[str] = []
        for p in content:
            if isinstance(p, str):
                parts.append(p)
                continue
            if isinstance(p, dict):
                t = p.get("type")
                if t in {"input_text", "text", "output_text"}:
                    parts.append(str(p.get("text") or ""))
                elif t in {"input_image", "image_url", "image"}:
                    url = p.get("image_url") or p.get("url") or p.get("imageUrl")
                    if url:
                        parts.append(f"[image] {url}")
                elif t in {"input_file", "file_url", "file"}:
                    url = p.get("file_url") or p.get("url") or p.get("fileUrl")
                    if url:
                        parts.append(f"[file] {url}")
                else:
                    if "text" in p and p["text"]:
                        parts.append(str(p["text"]))
        return "".join(parts).strip()
    return ""


def _messages_to_prompt(messages: List[dict]) -> str:
    """
    Trasforma una lista di messaggi OpenAI-like in una stringa.
    Nota: se usi sessionKey lato gateway, spesso NON serve includere history.
    Qui lo facciamo per compatibilità client-side.
    """
    lines: List[str] = []
    for m in messages:
        if not isinstance(m, dict):
            continue
        role = str(m.get("role") or "user")
        text = _extract_text_from_content(m.get("content"))
        if not text:
            continue
        lines.append(f"{role}: {text}")
    return "\n".join(lines).strip()


def _responses_payload_to_prompt(payload: dict) -> str:
    """
    Supporta OpenAI Responses:
    - input può essere string o lista messaggi
    - `instructions` viene anteposto come system
    """
    instructions = payload.get("instructions")
    sys_txt = ""
    if isinstance(instructions, str) and instructions.strip():
        sys_txt = f"system: {instructions.strip()}"

    inp = payload.get("input")
    prompt = ""
    if isinstance(inp, str):
        prompt = inp
    elif isinstance(inp, list):
        prompt = _messages_to_prompt(inp)
    elif isinstance(inp, dict):
        prompt = _messages_to_prompt([inp])

    prompt = (prompt or "").strip()
    if sys_txt:
        return (sys_txt + ("\n" + prompt if prompt else "")).strip()
    return prompt


def _chat_payload_to_prompt(payload: dict) -> str:
    """
    OpenAI ChatCompletions:
    - messages[] obbligatorio
    """
    messages = payload.get("messages") or []
    if isinstance(messages, list):
        return _messages_to_prompt(messages)
    return str(messages)


def _to_openclaw_simple_payload(prompt: str, *, stream: bool) -> Dict[str, Any]:
    return {"model": "openclaw", "input": prompt, "stream": bool(stream)}


# =============================================================================
# /v1/models
# =============================================================================

@router.get("/v1/models")
async def v1_models(user: AuthenticatedUser = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    convs = (
        await db.execute(
            select(Conversation)
            .where(Conversation.user_id == user.user_id, Conversation.is_deleted.is_(False))
            .order_by(Conversation.created_at.asc())
            .limit(200)
        )
    ).scalars().all()

    agents = sorted({(c.agent_id or settings.openclaw_default_agent_id) for c in convs})
    if not agents:
        agents = [settings.openclaw_default_agent_id]

    return JSONResponse(
        {
            "object": "list",
            "data": [{"id": f"openclaw:{a}", "object": "model", "owned_by": "openclaw"} for a in agents],
        }
    )


# =============================================================================
# /v1/responses (PROXY -> OpenClaw /v1/responses, ma SIMPLE)
# =============================================================================

@router.post("/v1/responses")
async def v1_responses(
    request: Request,
    x_bff_conversation_id: Optional[str] = Header(default=None, alias="x-bff-conversation-id"),
    x_openclaw_session_key: Optional[str] = Header(default=None, alias="x-openclaw-session-key"),
    x_openclaw_agent_id: Optional[str] = Header(default=None, alias="x-openclaw-agent-id"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Body must be a JSON object")

    if x_bff_conversation_id:
        conv = await _get_conversation_by_id(db, user.user_id, x_bff_conversation_id)
    else:
        alias = _infer_alias_from_payload(payload)
        conv = await _get_or_create_conversation_by_alias(db, user.user_id, alias)

    agent_override = _infer_agent_from_payload(payload)
    session_override: Optional[str] = None
    if settings.allow_raw_openclaw_session_key and x_openclaw_session_key:
        session_override = x_openclaw_session_key

    headers = _headers_for_conv(
        conv,
        agent_override=agent_override,
        agent_header_override=x_openclaw_agent_id,
        session_override=session_override,
    )

    prompt = _responses_payload_to_prompt(payload)
    if not prompt:
        raise HTTPException(
            status_code=400,
            detail={"error": {"message": "input: Invalid input", "type": "invalid_request_error"}},
        )

    stream = bool(payload.get("stream"))
    upstream_payload = _to_openclaw_simple_payload(prompt, stream=stream)

    if stream:
        async def _gen():
            try:
                async for b in stream_sse("/v1/responses", upstream_payload, headers=headers):
                    yield b
            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'message': str(e)})}\n\n".encode("utf-8")

        return StreamingResponse(_gen(), media_type="text/event-stream")

    try:
        resp = await post_json("/v1/responses", upstream_payload, headers=headers)
    except Exception as e:
        raise HTTPException(status_code=502, detail={"upstream": "openclaw", "message": str(e)})

    return JSONResponse(resp)


# =============================================================================
# /v1/chat/completions (IMPLEMENTATO VIA /v1/responses SIMPLE)
# =============================================================================

def _chat_completion_response(
    *,
    content: str,
    model: str,
    created: int,
    completion_id: str,
    prompt_tokens: Optional[int] = None,
    completion_tokens: Optional[int] = None,
    total_tokens: Optional[int] = None,
) -> dict:
    usage = None
    if total_tokens is not None:
        usage = {
            "prompt_tokens": int(prompt_tokens or 0),
            "completion_tokens": int(completion_tokens or 0),
            "total_tokens": int(total_tokens),
        }

    out = {
        "id": completion_id,
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
    }
    if usage is not None:
        out["usage"] = usage
    return out


def _chat_chunk(
    *,
    completion_id: str,
    model: str,
    created: int,
    delta: Optional[str] = None,
    role: Optional[str] = None,
    finish_reason: Optional[str] = None,
) -> dict:
    d: Dict[str, Any] = {}
    if role:
        d["role"] = role
    if delta is not None:
        d["content"] = delta
    return {
        "id": completion_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": d, "finish_reason": finish_reason}],
    }


@router.post("/v1/chat/completions")
async def v1_chat_completions(
    request: Request,
    x_bff_conversation_id: Optional[str] = Header(default=None, alias="x-bff-conversation-id"),
    x_openclaw_session_key: Optional[str] = Header(default=None, alias="x-openclaw-session-key"),
    x_openclaw_agent_id: Optional[str] = Header(default=None, alias="x-openclaw-agent-id"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Body must be a JSON object")

    if x_bff_conversation_id:
        conv = await _get_conversation_by_id(db, user.user_id, x_bff_conversation_id)
    else:
        alias = _infer_alias_from_payload(payload)
        conv = await _get_or_create_conversation_by_alias(db, user.user_id, alias)

    agent_override = _infer_agent_from_payload(payload)
    session_override: Optional[str] = None
    if settings.allow_raw_openclaw_session_key and x_openclaw_session_key:
        session_override = x_openclaw_session_key

    headers = _headers_for_conv(
        conv,
        agent_override=agent_override,
        agent_header_override=x_openclaw_agent_id,
        session_override=session_override,
    )

    prompt = _chat_payload_to_prompt(payload)
    if not prompt:
        raise HTTPException(
            status_code=400,
            detail={"error": {"message": "messages: Invalid input", "type": "invalid_request_error"}},
        )

    stream = bool(payload.get("stream"))
    upstream_payload = _to_openclaw_simple_payload(prompt, stream=stream)

    client_model = str(payload.get("model") or f"openclaw:{headers.get('x-openclaw-agent-id')}")

    if stream:
        completion_id = f"chatcmpl_{uuid.uuid4().hex}"
        created = int(time.time())

        async def _gen():
            yield f"data: {json.dumps(_chat_chunk(completion_id=completion_id, model=client_model, created=created, role='assistant'))}\n\n".encode("utf-8")
            try:
                async for ev in iter_sse_events(stream_sse("/v1/responses", upstream_payload, headers=headers)):
                    if ev.event.endswith("output_text.delta"):
                        try:
                            j = json.loads(ev.data)
                        except Exception:
                            continue
                        delta = j.get("delta") or j.get("text") or ""
                        if delta:
                            yield f"data: {json.dumps(_chat_chunk(completion_id=completion_id, model=client_model, created=created, delta=str(delta)))}\n\n".encode("utf-8")

                    if ev.event.endswith("completed"):
                        break

                yield f"data: {json.dumps(_chat_chunk(completion_id=completion_id, model=client_model, created=created, finish_reason='stop'))}\n\n".encode("utf-8")
                yield b"data: [DONE]\n\n"
            except Exception as e:
                err = {"error": {"message": str(e), "type": "api_error"}}
                yield f"data: {json.dumps(err)}\n\n".encode("utf-8")
                yield b"data: [DONE]\n\n"

        return StreamingResponse(_gen(), media_type="text/event-stream")

    try:
        resp = await post_json("/v1/responses", upstream_payload, headers=headers)
    except Exception as e:
        raise HTTPException(status_code=502, detail={"upstream": "openclaw", "message": str(e)})

    content = extract_output_text(resp)
    usage = resp.get("usage") if isinstance(resp, dict) else None

    return JSONResponse(
        _chat_completion_response(
            content=content,
            model=client_model,
            created=int(time.time()),
            completion_id=f"chatcmpl_{uuid.uuid4().hex}",
            prompt_tokens=(usage or {}).get("input_tokens") if isinstance(usage, dict) else None,
            completion_tokens=(usage or {}).get("output_tokens") if isinstance(usage, dict) else None,
            total_tokens=(usage or {}).get("total_tokens") if isinstance(usage, dict) else None,
        )
    )


# =============================================================================
# /tools/invoke (proxy)
# =============================================================================

@router.post("/tools/invoke")
async def tools_invoke(
    request: Request,
    x_bff_conversation_id: Optional[str] = Header(default=None, alias="x-bff-conversation-id"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Body must be a JSON object")

    if x_bff_conversation_id:
        conv = await _get_conversation_by_id(db, user.user_id, x_bff_conversation_id)
    else:
        alias = _infer_alias_from_payload(payload)
        conv = await _get_or_create_conversation_by_alias(db, user.user_id, alias)

    payload = dict(payload)
    payload.setdefault("sessionKey", conv.openclaw_session_key)

    try:
        resp = await post_json("/tools/invoke", payload)
    except Exception as e:
        raise HTTPException(status_code=502, detail={"upstream": "openclaw", "message": str(e)})

    return JSONResponse(resp)