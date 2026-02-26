from __future__ import annotations

import uuid
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.openclaw_http import post_json
from app.core.security import AuthenticatedUser, get_current_user
from app.db.models import Conversation
from app.db.session import get_db
from app.schemas.tools import ToolsCatalogResponse, ToolInvokeRequest, ToolInvokeResponse, ToolResultRequest

router = APIRouter()


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
    "/tools/catalog",
    summary="Catalogo tool disponibili",
    response_model=ToolsCatalogResponse,
)
async def tools_catalog(
    _: AuthenticatedUser = Depends(get_current_user),
):
    """Ritorna il catalogo tool dal gateway (best-effort).

    Il protocollo OpenClaw menziona un metodo `tools.catalog` disponibile in WS.
    Se non presente o se fallisce, ritorna lista vuota.
    """

    from app.main import get_ws_client

    ws = get_ws_client()
    await ws.connect()

    try:
        tools = await ws.call("tools.catalog", {})
        if isinstance(tools, dict) and "tools" in tools:
            return ToolsCatalogResponse(tools=tools.get("tools", []), source="ws")
        if isinstance(tools, list):
            return ToolsCatalogResponse(tools=tools, source="ws")
        return ToolsCatalogResponse(tools=[{"payload": tools}], source="ws")
    except Exception:
        return ToolsCatalogResponse(tools=[], source="fallback")


@router.post(
    "/conversations/{conversation_id}/tools/invoke",
    summary="Invoca un tool su OpenClaw (/tools/invoke)",
    response_model=ToolInvokeResponse,
)
async def invoke_tool(
    conversation_id: uuid.UUID,
    body: ToolInvokeRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ToolInvokeResponse:
    """Chiama direttamente l'endpoint OpenClaw `/tools/invoke`.

    OpenClaw consente `POST /tools/invoke` (sempre enabled) ma protetto da auth/policy.
    Se tool non è consentito, OpenClaw risponde `404` (come da documentazione).
    """

    conv = await _get_conversation_or_404(db, user.user_id, conversation_id)

    payload: Dict[str, Any] = {
        "tool": body.tool,
        "action": body.action,
        "args": body.args,
        "sessionKey": conv.openclaw_session_key,
    }

    try:
        res = await post_json("/tools/invoke", payload)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"OpenClaw /tools/invoke failed: {e}")

    return ToolInvokeResponse(openclaw_result=res)


@router.post(
    "/conversations/{conversation_id}/tool-results",
    summary="Invia output tool a OpenResponses e continua la conversazione",
    response_model=dict,
)
async def tool_results(
    conversation_id: uuid.UUID,
    body: ToolResultRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    stream: bool = Query(default=False, description="Se true, richiede stream SSE al gateway (non proxato qui)")
) -> dict:
    """Invia a OpenClaw un `function_call_output` e richiede continuazione.

    Implementazione: POST /v1/responses con input role=tool.
    """

    conv = await _get_conversation_or_404(db, user.user_id, conversation_id)

    payload = {
        "model": f"openclaw:{conv.agent_id or settings.openclaw_default_agent_id}",
        "input": [
            {
                "role": "tool",
                "content": [
                    {
                        "type": "function_call_output",
                        "call_id": body.call_id,
                        "output": body.output,
                    }
                ],
            }
        ],
        "stream": bool(stream),
    }

    headers = {
        "x-openclaw-session-key": conv.openclaw_session_key,
        "x-openclaw-agent-id": conv.agent_id or settings.openclaw_default_agent_id,
    }

    try:
        res = await post_json("/v1/responses", payload, headers=headers)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"OpenClaw /v1/responses failed: {e}")

    return res
