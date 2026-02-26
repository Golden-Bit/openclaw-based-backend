from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.openclaw_http import post_json, stream_sse
from app.core.security import AuthenticatedUser, get_current_user
from app.db.models import Conversation, ConversationAlias
from app.db.session import get_db

router = APIRouter()


async def _get_or_create_conversation_by_alias(
    db: AsyncSession,
    user_id: str,
    alias: str,
) -> Conversation:
    alias_row = (await db.execute(
        select(ConversationAlias).where(ConversationAlias.user_id == user_id, ConversationAlias.alias == alias)
    )).scalars().first()

    if alias_row:
        conv = (await db.execute(select(Conversation).where(Conversation.id == alias_row.conversation_id))).scalars().first()
        if conv and not conv.is_deleted:
            return conv

    # create new conversation
    conv_id = uuid.uuid4()
    session_key = f"bff:{conv_id}"
    conv = Conversation(
        id=conv_id,
        user_id=user_id,
        title=None,
        agent_id=settings.openclaw_default_agent_id,
        openclaw_session_key=session_key,
    )
    db.add(conv)
    await db.flush()

    db.add(ConversationAlias(user_id=user_id, alias=alias, conversation_id=conv_id))
    await db.commit()
    await db.refresh(conv)
    return conv


async def _get_conversation_by_id(db: AsyncSession, user_id: str, conversation_id: str) -> Conversation:
    try:
        cid = uuid.UUID(conversation_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid conversation_id")

    conv = (await db.execute(
        select(Conversation).where(
            Conversation.id == cid,
            Conversation.user_id == user_id,
            Conversation.is_deleted.is_(False),
        )
    )).scalars().first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conv


def _infer_alias_from_payload(payload: Dict[str, Any]) -> str:
    # OpenAI provides optional `user` field.
    u = payload.get("user")
    if isinstance(u, str) and u.strip():
        return u.strip()
    return "default"


def _infer_agent_from_payload(payload: Dict[str, Any]) -> Optional[str]:
    model = payload.get("model")
    if isinstance(model, str) and model:
        if model.startswith("openclaw:"):
            return model.split(":", 1)[1]
        return model
    return None


@router.get(
    "/v1/models",
    summary="OpenAI-compatible: list models (agents)",
)
async def v1_models(
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Ritorna una lista modelli compatibile OpenAI.

    Per OpenClaw, esponiamo gli **agent** come modelli `openclaw:<agentId>`.
    """

    from app.main import get_ws_client

    ws = get_ws_client()
    try:
        await ws.connect()
        agents = await ws.call("agents.list", {})
        agent_list = []
        if isinstance(agents, dict):
            agent_list = agents.get("agents", [])
        elif isinstance(agents, list):
            agent_list = agents

        data = []
        now = int(datetime.utcnow().timestamp())
        for a in agent_list:
            aid = a.get("id") if isinstance(a, dict) else None
            if not aid:
                continue
            data.append({"id": f"openclaw:{aid}", "object": "model", "created": now, "owned_by": "openclaw"})

        # fallback
        if not data:
            data = [{"id": f"openclaw:{settings.openclaw_default_agent_id}", "object": "model", "created": now, "owned_by": "openclaw"}]

        return {"object": "list", "data": data}
    except Exception:
        now = int(datetime.utcnow().timestamp())
        return {"object": "list", "data": [{"id": f"openclaw:{settings.openclaw_default_agent_id}", "object": "model", "created": now, "owned_by": "openclaw"}]}


@router.post(
    "/v1/responses",
    summary="OpenAI-compatible: Responses (proxy verso OpenClaw)",
)
async def v1_responses(
    request: Request,
    payload: Dict[str, Any] = Body(..., description="Payload OpenAI Responses-like", examples=[{
            "model": "openclaw:main",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "Ciao"}]}],
            "stream": True,
            "user": "default"
        }]),
    x_bff_conversation_id: Optional[str] = Header(default=None, alias="x-bff-conversation-id"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Proxy verso OpenClaw `/v1/responses`.

    Routing conversazione:
    - se header `x-bff-conversation-id` presente: usa quella conversazione (ownership check)
    - altrimenti usa `payload.user` come alias (o `default`)

    Il BFF imposta `x-openclaw-session-key` e `x-openclaw-agent-id`.

    Se `payload.stream=true` il BFF proxy lo stream SSE **grezzo** (massima compatibilità).
    """

    if x_bff_conversation_id:
        conv = await _get_conversation_by_id(db, user.user_id, x_bff_conversation_id)
    else:
        alias = _infer_alias_from_payload(payload)
        conv = await _get_or_create_conversation_by_alias(db, user.user_id, alias)

    agent = _infer_agent_from_payload(payload) or conv.agent_id or settings.openclaw_default_agent_id

    headers = {
        "x-openclaw-session-key": conv.openclaw_session_key,
        "x-openclaw-agent-id": agent,
    }

    # Optionally disallow clients from forcing raw sessionKey
    if settings.allow_raw_openclaw_session_key:
        raw = request.headers.get("x-openclaw-session-key")
        if raw:
            headers["x-openclaw-session-key"] = raw

    stream = bool(payload.get("stream"))

    if stream:
        async def gen() -> AsyncGenerator[bytes, None]:
            async for chunk in stream_sse("/v1/responses", payload, headers=headers):
                yield chunk

        return StreamingResponse(gen(), media_type="text/event-stream")

    resp = await post_json("/v1/responses", payload, headers=headers)
    return JSONResponse(resp)


@router.post(
    "/v1/chat/completions",
    summary="OpenAI-compatible: Chat Completions (proxy verso OpenClaw)",
)
async def v1_chat_completions(
    request: Request,
    payload: Dict[str, Any] = Body(..., description="Payload OpenAI ChatCompletions-like", examples=[{
            "model": "openclaw:main",
            "messages": [{"role": "user", "content": "Ciao"}],
            "stream": True,
            "user": "default"
        }]),
    x_bff_conversation_id: Optional[str] = Header(default=None, alias="x-bff-conversation-id"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Proxy verso OpenClaw `/v1/chat/completions`.

    Stessa logica routing di `/v1/responses`.

    Streaming: se `stream=true` proxy SSE grezzo.
    """

    if x_bff_conversation_id:
        conv = await _get_conversation_by_id(db, user.user_id, x_bff_conversation_id)
    else:
        alias = _infer_alias_from_payload(payload)
        conv = await _get_or_create_conversation_by_alias(db, user.user_id, alias)

    agent = _infer_agent_from_payload(payload) or conv.agent_id or settings.openclaw_default_agent_id

    headers = {
        "x-openclaw-session-key": conv.openclaw_session_key,
        "x-openclaw-agent-id": agent,
    }

    if settings.allow_raw_openclaw_session_key:
        raw = request.headers.get("x-openclaw-session-key")
        if raw:
            headers["x-openclaw-session-key"] = raw

    stream = bool(payload.get("stream"))

    if stream:
        async def gen() -> AsyncGenerator[bytes, None]:
            async for chunk in stream_sse("/v1/chat/completions", payload, headers=headers):
                yield chunk

        return StreamingResponse(gen(), media_type="text/event-stream")

    resp = await post_json("/v1/chat/completions", payload, headers=headers)
    return JSONResponse(resp)


@router.post(
    "/tools/invoke",
    summary="OpenAI-compatible: /tools/invoke (proxy verso OpenClaw)",
)
async def tools_invoke_proxy(
    payload: Dict[str, Any] = Body(..., description="Payload OpenClaw /tools/invoke", examples=[{
            "tool": "browser",
            "action": "open",
            "args": {"url": "https://example.com"},
            "user": "default"
        }]),
    x_bff_conversation_id: Optional[str] = Header(default=None, alias="x-bff-conversation-id"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Proxy verso OpenClaw `/tools/invoke`.

    Se `sessionKey` non è presente nel body, il BFF lo inserisce dalla conversazione.
    """

    if x_bff_conversation_id:
        conv = await _get_conversation_by_id(db, user.user_id, x_bff_conversation_id)
    else:
        alias = _infer_alias_from_payload(payload)
        conv = await _get_or_create_conversation_by_alias(db, user.user_id, alias)

    payload = dict(payload)
    payload.setdefault("sessionKey", conv.openclaw_session_key)

    resp = await post_json("/tools/invoke", payload)
    return JSONResponse(resp)
