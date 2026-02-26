from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sse_starlette.sse import EventSourceResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.openclaw_http import post_json, stream_sse
from app.core.security import AuthenticatedUser, get_current_user
from app.db.models import Conversation, Message
from app.db.session import get_db
from app.schemas.messages import (
    AbortRequest,
    AbortResponse,
    InjectRequest,
    InjectResponse,
    MessageItem,
    SendMessageRequest,
    SendMessageResponse,
    StreamMessageRequest,
)
from app.utils.openresponses import extract_output_text
from app.utils.sse import format_sse, iter_sse_events

router = APIRouter(prefix="/conversations/{conversation_id}")


def _build_openresponses_payload(text: str, attachments: Optional[list[dict]] = None, model: Optional[str] = None, stream: bool = False) -> Dict[str, Any]:
    """Costruisce una request compatibile OpenResponses (best-effort)."""

    content: List[Dict[str, Any]] = [{"type": "input_text", "text": text}]

    for att in attachments or []:
        att_type = att.get("type")
        url = att.get("url")
        if not att_type or not url:
            continue
        if att_type == "input_image":
            content.append({"type": "input_image", "image_url": url})
        elif att_type == "input_file":
            content.append({"type": "input_file", "file_url": url})
        else:
            # fallback generico
            content.append({"type": att_type, "url": url})

    payload: Dict[str, Any] = {
        "model": model or f"openclaw:{settings.openclaw_default_agent_id}",
        "input": [{"role": "user", "content": content}],
        "stream": bool(stream),
    }
    return payload


async def _get_conversation_or_404(db: AsyncSession, user_id: str, conversation_id: uuid.UUID) -> Conversation:
    conv = (await db.execute(
        select(Conversation).where(
            Conversation.id == conversation_id,
            Conversation.user_id == user_id,
            Conversation.is_deleted.is_(False),
        )
    )).scalars().first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conv


@router.get(
    "/messages",
    summary="Elenca messaggi della conversazione",
    response_model=List[MessageItem],
)
async def list_messages(
    conversation_id: uuid.UUID,
    source: str = Query(default="db", description="Sorgente: db | gateway"),
    limit: int = Query(default=200, ge=1, le=1000),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[MessageItem]:
    """Ritorna i messaggi.

    - `source=db`: legge dal DB del BFF
    - `source=gateway`: tenta `chat.history` via WS su OpenClaw e ritorna una rappresentazione (best-effort)

    Nota: il formato gateway può differire; per UI stabile è preferibile usare `source=db`.
    """

    conv = await _get_conversation_or_404(db, user.user_id, conversation_id)

    if source == "gateway":
        # best-effort WS history
        from app.main import get_ws_client

        ws = get_ws_client()
        await ws.connect()
        try:
            payload = await ws.call("chat.history", {"sessionKey": conv.openclaw_session_key, "limit": limit})
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"OpenClaw WS chat.history failed: {e}")

        msgs = []
        for m in payload.get("messages", []) if isinstance(payload, dict) else []:
            # mapping minimo
            msgs.append(
                MessageItem(
                    id=uuid.uuid4(),
                    role=m.get("role", "assistant"),
                    content=m.get("content") or m.get("text"),
                    raw=m,
                    run_id=m.get("runId"),
                    seq=m.get("seq"),
                    created_at=datetime.utcnow(),
                )
            )
        return msgs

    # default: DB
    stmt = (
        select(Message)
        .where(Message.conversation_id == conv.id)
        .order_by(Message.created_at.asc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [
        MessageItem(
            id=r.id,
            role=r.role,
            content=r.content,
            raw=r.raw,
            run_id=r.run_id,
            seq=r.seq,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.post(
    "/messages",
    summary="Invia un messaggio (non streaming)",
    response_model=SendMessageResponse,
)
async def send_message(
    conversation_id: uuid.UUID,
    body: SendMessageRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SendMessageResponse:
    """Invia un messaggio utente e ritorna la risposta finale (no stream)."""

    conv = await _get_conversation_or_404(db, user.user_id, conversation_id)

    # Persist user message
    db.add(Message(conversation_id=conv.id, role="user", content=body.content, raw={"attachments": [a.model_dump() for a in (body.attachments or [])]}))
    await db.commit()

    payload = _build_openresponses_payload(
        body.content,
        attachments=[a.model_dump() for a in (body.attachments or [])],
        model=f"openclaw:{conv.agent_id or settings.openclaw_default_agent_id}",
        stream=False,
    )

    headers = {
        "x-openclaw-session-key": conv.openclaw_session_key,
        "x-openclaw-agent-id": conv.agent_id or settings.openclaw_default_agent_id,
    }

    resp = await post_json("/v1/responses", payload, headers=headers)
    assistant_text = extract_output_text(resp)

    # Persist assistant
    db.add(Message(conversation_id=conv.id, role="assistant", content=assistant_text, raw=resp))
    await db.commit()

    return SendMessageResponse(conversation_id=conv.id, assistant_text=assistant_text, openclaw_response=resp)


@router.post(
    "/messages/stream",
    summary="Invia un messaggio (stream SSE)",
    description="Proxy SSE verso OpenClaw /v1/responses (stream:true).",
)
async def send_message_stream(
    conversation_id: uuid.UUID,
    body: StreamMessageRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Streaming SSE.

    Il backend:
    - salva il messaggio utente in DB
    - chiama OpenClaw `/v1/responses` con `stream:true`
    - proxy SSE verso FE
    - (opzionale) salva il testo finale assistente in DB

    Eventi SSE emessi verso FE:
    - `message.delta`: data={"delta":"..."}
    - `message.completed`: data={"text":"..."}
    - `openclaw.<event>`: evento originale del gateway (debug)
    - `error`
    """

    conv = await _get_conversation_or_404(db, user.user_id, conversation_id)

    # Persist user message
    db.add(Message(conversation_id=conv.id, role="user", content=body.content, raw={"attachments": [a.model_dump() for a in (body.attachments or [])]}))
    await db.commit()

    payload = _build_openresponses_payload(
        body.content,
        attachments=[a.model_dump() for a in (body.attachments or [])],
        model=f"openclaw:{conv.agent_id or settings.openclaw_default_agent_id}",
        stream=True,
    )

    headers = {
        "x-openclaw-session-key": conv.openclaw_session_key,
        "x-openclaw-agent-id": conv.agent_id or settings.openclaw_default_agent_id,
    }

    async def event_generator() -> AsyncGenerator[Dict[str, str], None]:
        assistant_accum = ""
        try:
            byte_stream = stream_sse("/v1/responses", payload, headers=headers)
            async for ev in iter_sse_events(byte_stream):
                # Forward original event for debugging
                yield {"event": f"openclaw.{ev.event}", "data": ev.data}

                # Translate known events into UI-friendly deltas
                if ev.event.endswith("output_text.delta"):
                    try:
                        j = json.loads(ev.data)
                        delta = j.get("delta") or j.get("text") or ""
                    except Exception:
                        delta = ""
                    if delta:
                        assistant_accum += delta
                        yield {"event": "message.delta", "data": json.dumps({"delta": delta})}

                if ev.event.endswith("completed"):
                    # Try to parse final
                    yield {"event": "message.completed", "data": json.dumps({"text": assistant_accum})}

        except Exception as e:  # noqa: BLE001
            yield {"event": "error", "data": json.dumps({"message": str(e)})}
        finally:
            if settings.persist_streamed_messages and assistant_accum:
                db.add(Message(conversation_id=conv.id, role="assistant", content=assistant_accum, raw={"streamed": True}))
                await db.commit()

    return EventSourceResponse(event_generator())


@router.post(
    "/abort",
    summary="Interrompe un run in corso",
    response_model=AbortResponse,
)
async def abort_run(
    conversation_id: uuid.UUID,
    body: AbortRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AbortResponse:
    conv = await _get_conversation_or_404(db, user.user_id, conversation_id)

    from app.main import get_ws_client

    ws = get_ws_client()
    await ws.connect()
    params: Dict[str, Any] = {"sessionKey": conv.openclaw_session_key}
    if body.run_id:
        params["runId"] = body.run_id

    try:
        res = await ws.call("chat.abort", params)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"OpenClaw WS chat.abort failed: {e}")

    return AbortResponse(aborted=True, openclaw_result=res if isinstance(res, dict) else {"payload": res})


@router.post(
    "/inject",
    summary="Inietta un messaggio (system/assistant) nel thread",
    response_model=InjectResponse,
)
async def inject_message(
    conversation_id: uuid.UUID,
    body: InjectRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> InjectResponse:
    conv = await _get_conversation_or_404(db, user.user_id, conversation_id)

    from app.main import get_ws_client

    ws = get_ws_client()
    await ws.connect()

    params: Dict[str, Any] = {"sessionKey": conv.openclaw_session_key, "message": body.content}
    if body.label:
        params["label"] = body.label

    try:
        res = await ws.call("chat.inject", params)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"OpenClaw WS chat.inject failed: {e}")

    # Persist injected message (as system)
    db.add(Message(conversation_id=conv.id, role="system", content=body.content, raw={"label": body.label}))
    await db.commit()

    return InjectResponse(injected=True, openclaw_result=res if isinstance(res, dict) else {"payload": res})
