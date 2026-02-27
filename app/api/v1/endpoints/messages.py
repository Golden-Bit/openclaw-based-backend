from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from sse_starlette.sse import EventSourceResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.openclaw_http import OpenClawHTTPError, is_invalid_input_error, post_json, stream_sse
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
from app.utils.sse import iter_sse_events

router = APIRouter(prefix="/conversations/{conversation_id}")


# =============================================================================
# Payload builders (structured vs simple)
# =============================================================================

def _build_openresponses_payload_structured(
    text: str,
    attachments: Optional[list[dict]] = None,
    model: Optional[str] = None,
    stream: bool = False,
) -> Dict[str, Any]:
    """
    Payload "OpenAI Responses-like" (structured).
    ATTENZIONE: la tua build OpenClaw attuale risponde 400 "input: Invalid input" su questo formato.
    Lo teniamo per:
      - futuro supporto
      - fallback/compat con build diverse
    """
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
            content.append({"type": att_type, "url": url})

    payload: Dict[str, Any] = {
        "model": model or f"openclaw:{settings.openclaw_default_agent_id}",
        "input": [{"role": "user", "content": content}],
        "stream": bool(stream),
    }
    return payload


def _build_openresponses_payload_simple(
    text: str,
    attachments: Optional[list[dict]] = None,
    stream: bool = False,
) -> Dict[str, Any]:
    """
    Payload "simple" compatibile con build OpenClaw che NON supportano input structured.
    Qui usiamo:
      - model: "openclaw"
      - input: string
    """
    extra_lines: List[str] = []
    for att in attachments or []:
        att_type = att.get("type")
        url = att.get("url")
        if not att_type or not url:
            continue
        extra_lines.append(f"[attachment:{att_type}] {url}")

    joined = text
    if extra_lines:
        joined = text + "\n\n" + "\n".join(extra_lines)

    return {
        "model": "openclaw",
        "input": joined,
        "stream": bool(stream),
    }


def _openclaw_headers_for_conversation(conv: Conversation) -> Dict[str, str]:
    """
    Header OpenClaw per:
      - session key (se presente) per continuare lo stesso thread lato gateway
      - agent id (sempre) per selezionare l'agente
    """
    agent_id = conv.agent_id or settings.openclaw_default_agent_id
    h: Dict[str, str] = {
        "x-openclaw-agent-id": agent_id,
    }
    if conv.openclaw_session_key:
        h["x-openclaw-session-key"] = conv.openclaw_session_key
    return h


async def _call_openclaw_responses_with_fallback(
    conv: Conversation,
    text: str,
    attachments: Optional[list[dict]],
    stream: bool,
) -> Tuple[dict, str]:
    """
    Chiama OpenClaw /v1/responses provando:
      A) structured (openclaw:<agent>)  -> se 400 invalid input => fallback
      B) simple (model=openclaw,input=string)

    Ritorna:
      (response_json, mode_used) dove mode_used in {"structured","simple"}.

    Se fallisce anche fallback, solleva HTTPException 502 con dettaglio upstream.
    """
    headers = _openclaw_headers_for_conversation(conv)

    # Candidate A: structured (con model openclaw:<agent>)
    payload_a = _build_openresponses_payload_structured(
        text,
        attachments=attachments,
        model=f"openclaw:{conv.agent_id or settings.openclaw_default_agent_id}",
        stream=stream,
    )

    try:
        resp = await post_json("/v1/responses", payload_a, headers=headers)
        return resp, "structured"
    except OpenClawHTTPError as e:
        # Se è "invalid input", facciamo fallback al semplice.
        if e.status_code == 400 and is_invalid_input_error(e.error):
            payload_b = _build_openresponses_payload_simple(text, attachments=attachments, stream=stream)
            try:
                resp = await post_json("/v1/responses", payload_b, headers=headers)
                return resp, "simple"
            except OpenClawHTTPError as e2:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "upstream": "openclaw",
                        "where": "responses.simple",
                        "status": e2.status_code,
                        "url": e2.url,
                        "error": e2.error,
                    },
                )
        # Altri errori: propaga come 502 con dettaglio
        raise HTTPException(
            status_code=502,
            detail={
                "upstream": "openclaw",
                "where": "responses.structured",
                "status": e.status_code,
                "url": e.url,
                "error": e.error,
            },
        )


async def _stream_openclaw_responses_with_fallback(
    conv: Conversation,
    text: str,
    attachments: Optional[list[dict]],
) -> AsyncGenerator[bytes, None]:
    """
    Streaming SSE con fallback:
      A) structured stream:true -> se 400 invalid input => B) simple stream:true

    Ritorna generator di bytes SSE.
    """
    headers = _openclaw_headers_for_conversation(conv)

    payload_a = _build_openresponses_payload_structured(
        text,
        attachments=attachments,
        model=f"openclaw:{conv.agent_id or settings.openclaw_default_agent_id}",
        stream=True,
    )

    try:
        async for b in stream_sse("/v1/responses", payload_a, headers=headers):
            yield b
        return
    except OpenClawHTTPError as e:
        if e.status_code == 400 and is_invalid_input_error(e.error):
            payload_b = _build_openresponses_payload_simple(text, attachments=attachments, stream=True)
            async for b in stream_sse("/v1/responses", payload_b, headers=headers):
                yield b
            return

        # altri errori: rilancia e lo gestiremo a livello superiore
        raise


# =============================================================================
# DB helpers
# =============================================================================

async def _get_conversation_or_404(db: AsyncSession, user_id: str, conversation_id: uuid.UUID) -> Conversation:
    conv = (
        await db.execute(
            select(Conversation).where(
                Conversation.id == conversation_id,
                Conversation.user_id == user_id,
                Conversation.is_deleted.is_(False),
            )
        )
    ).scalars().first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conv


# =============================================================================
# Endpoints
# =============================================================================

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

    - source=db: legge dal DB del BFF
    - source=gateway: tenta chat.history via WS su OpenClaw (best-effort)

    Nota: per UI stabile è preferibile source=db.
    """
    conv = await _get_conversation_or_404(db, user.user_id, conversation_id)

    if source == "gateway":
        from app.main import get_ws_client

        ws = get_ws_client()
        await ws.connect()
        try:
            payload = await ws.call("chat.history", {"sessionKey": conv.openclaw_session_key, "limit": limit})
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"OpenClaw WS chat.history failed: {e}")

        msgs = []
        for m in payload.get("messages", []) if isinstance(payload, dict) else []:
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

    # default DB
    stmt = select(Message).where(Message.conversation_id == conv.id).order_by(Message.created_at.asc()).limit(limit)
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
    db.add(
        Message(
            conversation_id=conv.id,
            role="user",
            content=body.content,
            raw={"attachments": [a.model_dump() for a in (body.attachments or [])]},
        )
    )
    await db.commit()

    # Call OpenClaw with fallback (structured -> simple)
    resp, mode_used = await _call_openclaw_responses_with_fallback(
        conv,
        body.content,
        attachments=[a.model_dump() for a in (body.attachments or [])],
        stream=False,
    )

    assistant_text = extract_output_text(resp)

    # Persist assistant
    db.add(
        Message(
            conversation_id=conv.id,
            role="assistant",
            content=assistant_text,
            raw={"openclaw": resp, "mode_used": mode_used},
        )
    )
    await db.commit()

    return SendMessageResponse(conversation_id=conv.id, assistant_text=assistant_text, openclaw_response=resp)


@router.post(
    "/messages/stream",
    summary="Invia un messaggio (stream SSE)",
    description="Proxy SSE verso OpenClaw /v1/responses (stream:true) con fallback payload.",
)
async def send_message_stream(
    conversation_id: uuid.UUID,
    body: StreamMessageRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Streaming SSE.

    - salva il messaggio utente in DB
    - chiama OpenClaw `/v1/responses` con `stream:true` (fallback se input structured non supportato)
    - proxy SSE verso FE
    - salva il testo finale assistente in DB (se persist_streamed_messages)
    """
    conv = await _get_conversation_or_404(db, user.user_id, conversation_id)

    # Persist user message
    db.add(
        Message(
            conversation_id=conv.id,
            role="user",
            content=body.content,
            raw={"attachments": [a.model_dump() for a in (body.attachments or [])]},
        )
    )
    await db.commit()

    async def event_generator() -> AsyncGenerator[Dict[str, str], None]:
        assistant_accum = ""
        try:
            byte_stream = _stream_openclaw_responses_with_fallback(
                conv,
                body.content,
                attachments=[a.model_dump() for a in (body.attachments or [])],
            )

            async for ev in iter_sse_events(byte_stream):
                # forward original event for debugging
                yield {"event": f"openclaw.{ev.event}", "data": ev.data}

                # translate known events into deltas
                # Nota: i nomi event possono variare; qui gestiamo pattern comuni
                if ev.event.endswith("output_text.delta") or ev.event.endswith("response.output_text.delta"):
                    try:
                        j = json.loads(ev.data)
                        delta = j.get("delta") or j.get("text") or ""
                    except Exception:
                        delta = ""
                    if delta:
                        assistant_accum += delta
                        yield {"event": "message.delta", "data": json.dumps({"delta": delta})}

                if ev.event.endswith("completed") or ev.event.endswith("response.completed"):
                    yield {"event": "message.completed", "data": json.dumps({"text": assistant_accum})}

        except OpenClawHTTPError as e:
            # errore upstream dettagliato
            yield {
                "event": "error",
                "data": json.dumps(
                    {"upstream": "openclaw", "status": e.status_code, "url": e.url, "error": e.error}
                ),
            }
        except Exception as e:  # noqa: BLE001
            yield {"event": "error", "data": json.dumps({"message": str(e)})}
        finally:
            if settings.persist_streamed_messages and assistant_accum:
                db.add(
                    Message(
                        conversation_id=conv.id,
                        role="assistant",
                        content=assistant_accum,
                        raw={"streamed": True},
                    )
                )
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