from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sse_starlette.sse import EventSourceResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.openclaw_ws import WSEvent
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

router = APIRouter(prefix="/conversations/{conversation_id}")


# =============================================================================
# OpenClaw WS Agent Loop bridge
# =============================================================================


def _agent_id(conv: Conversation) -> str:
    return conv.agent_id or settings.openclaw_default_agent_id


def _extract_text_delta(ev: WSEvent) -> str:
    """Best-effort: estrae delta testuale dagli eventi agent.

    Shape dipende dalla build. Pattern gestiti:
    - payload.stream in ['assistant','text','reasoning']
    - payload.data contiene 'delta' o 'text'
    """

    p = ev.payload
    stream = str(p.get("stream") or "")
    if stream not in {"assistant", "text", "reasoning"}:
        return ""
    data = p.get("data") or {}
    if isinstance(data, str):
        return data
    if not isinstance(data, dict):
        return ""
    return str(data.get("delta") or data.get("text") or "")


def _is_lifecycle_done(ev: WSEvent) -> bool:
    p = ev.payload
    if str(p.get("stream") or "") != "lifecycle":
        return False
    data = p.get("data")
    if not isinstance(data, dict):
        return False
    phase = str(data.get("phase") or data.get("status") or "").lower()
    typ = str(data.get("type") or "").lower()
    return phase in {"done", "completed", "complete", "end", "finished"} or typ in {
        "completed",
        "done",
        "run.completed",
        "agent.completed",
    }


def _tool_event_payload(ev: WSEvent) -> Optional[dict]:
    p = ev.payload
    if str(p.get("stream") or "") != "tool":
        return None
    data = p.get("data")
    if isinstance(data, dict):
        return data
    return {"raw": data}


async def _run_agent_and_collect(
    ws,
    *,
    agent_id: str,
    session_key: Optional[str],
    message: str,
    timeout_s: float = 120.0,
) -> tuple[str, list[dict], str]:
    """Esegue un turn agentico via WS e raccoglie testo + eventi tool."""

    # OpenClaw richiede un idempotencyKey per l'RPC `agent` (schema strict).
    # In caso di retry lato client (es. FE), usare sempre lo stesso valore.
    params: Dict[str, Any] = {
        "agentId": agent_id,
        "message": message,
        "idempotencyKey": uuid.uuid4().hex,
    }
    if session_key:
        params["sessionKey"] = session_key

    run = await ws.call("agent", params)
    if not isinstance(run, dict):
        raise RuntimeError(f"Unexpected agent() response: {run!r}")
    run_id = str(run.get("runId") or run.get("id") or "")
    if not run_id:
        raise RuntimeError(f"agent() did not return runId: {run!r}")

    assistant_accum = ""
    tool_events: list[dict] = []

    wait_task: Optional[asyncio.Task] = None
    try:
        wait_task = asyncio.create_task(
            ws.call("agent.wait", {"runId": run_id, "timeoutMs": int(timeout_s * 1000)})
        )
    except Exception:
        wait_task = None

    async for ev in ws.subscribe("agent", run_id=run_id):
        d = _extract_text_delta(ev)
        if d:
            assistant_accum += d

        te = _tool_event_payload(ev)
        if te is not None:
            tool_events.append(te)

        if _is_lifecycle_done(ev):
            break

        if wait_task and wait_task.done():
            break

    if wait_task:
        try:
            await asyncio.wait_for(wait_task, timeout=1.0)
        except Exception:
            pass

    return assistant_accum, tool_events, run_id


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
    """Invia un messaggio utente e ritorna la risposta finale (no stream).

    Differenza chiave rispetto al vecchio comportamento:
    - NON chiama più /v1/responses HTTP
    - usa WS Agent Loop (`agent` + stream `event: agent`) così possiamo catturare tool events.
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

    from app.main import get_ws_client

    ws = get_ws_client()
    await ws.connect()

    assistant_text, tool_events, run_id = await _run_agent_and_collect(
        ws,
        agent_id=_agent_id(conv),
        session_key=conv.openclaw_session_key,
        message=body.content,
    )

    # Persist assistant
    db.add(
        Message(
            conversation_id=conv.id,
            role="assistant",
            content=assistant_text,
            raw={"run_id": run_id, "tool_events": tool_events},
        )
    )
    await db.commit()

    # openclaw_response: best-effort structure (non è più la risposta OpenResponses HTTP)
    openclaw_response = {
        "object": "agent.run",
        "run_id": run_id,
        "agent_id": _agent_id(conv),
        "session_key": conv.openclaw_session_key,
        "output_text": assistant_text,
        "tool_events": tool_events,
    }

    return SendMessageResponse(
        conversation_id=conv.id,
        assistant_text=assistant_text,
        openclaw_response=openclaw_response,
    )


@router.post(
    "/messages/stream",
    summary="Invia un messaggio (stream SSE)",
    description="Bridge WS Agent Loop -> SSE (include tool events).",
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
    - invoca WS `agent`
    - ascolta eventi `event: agent` filtrati per runId
    - re-emette SSE verso FE includendo tool events
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
        from app.main import get_ws_client

        ws = get_ws_client()
        assistant_accum = ""
        tool_events: list[dict] = []

        try:
            await ws.connect()

            params: Dict[str, Any] = {
                "agentId": _agent_id(conv),
                "message": body.content,
                "idempotencyKey": uuid.uuid4().hex,
            }
            if conv.openclaw_session_key:
                params["sessionKey"] = conv.openclaw_session_key

            run = await ws.call("agent", params)
            run_id = str(run.get("runId") or run.get("id") or "") if isinstance(run, dict) else ""
            if not run_id:
                raise RuntimeError(f"agent() did not return runId: {run!r}")

            # wait in background (best-effort)
            wait_task: Optional[asyncio.Task] = None
            try:
                wait_task = asyncio.create_task(
                    ws.call("agent.wait", {"runId": run_id, "timeoutMs": 10 * 60 * 1000})
                )
            except Exception:
                wait_task = None

            async for ev in ws.subscribe("agent", run_id=run_id):
                # 1) evento raw (debug)
                yield {"event": "openclaw.agent", "data": json.dumps(ev.payload)}

                # 2) tool events
                te = _tool_event_payload(ev)
                if te is not None:
                    tool_events.append(te)
                    yield {"event": "tool.event", "data": json.dumps({"run_id": run_id, **te})}

                # 3) text delta
                delta = _extract_text_delta(ev)
                if delta:
                    assistant_accum += delta
                    yield {"event": "message.delta", "data": json.dumps({"delta": delta})}

                if _is_lifecycle_done(ev):
                    break

                if wait_task and wait_task.done():
                    break

            # ensure wait task done (ignore errors)
            if wait_task:
                try:
                    await asyncio.wait_for(wait_task, timeout=1.0)
                except Exception:
                    pass

            yield {"event": "message.completed", "data": json.dumps({"text": assistant_accum})}

        except Exception as e:  # noqa: BLE001
            yield {"event": "error", "data": json.dumps({"message": str(e)})}

        finally:
            if settings.persist_streamed_messages and assistant_accum:
                db.add(
                    Message(
                        conversation_id=conv.id,
                        role="assistant",
                        content=assistant_accum,
                        raw={"streamed": True, "tool_events": tool_events},
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
