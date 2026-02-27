from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import AuthenticatedUser, get_current_user
from app.db.session import get_db

router = APIRouter()


@router.get(
    "/health",
    summary="Healthcheck (BFF + DB + OpenClaw)",
    response_model=dict,
)
async def health(
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Healthcheck.

    - db_ok: verifica DB con `SELECT 1`
    - openclaw_ws_ok: tenta connect WS verso OpenClaw
    - openclaw_ws_detail: dettagli utili se fallisce (error + type)
      Nota: il metodo RPC "health" potrebbe non esistere su tutte le build, quindi è best-effort.
    """
    # DB check
    db_ok = True
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        db_ok = False

    # OpenClaw WS check
    openclaw_ws_ok = False
    openclaw_ws_detail: Optional[dict] = None

    try:
        from app.main import get_ws_client

        ws = get_ws_client()
        hello = await ws.connect()
        openclaw_ws_ok = hello is not None

        # Best-effort: prova un RPC "health"
        try:
            openclaw_ws_detail = await ws.call("health", {})
        except Exception as e:
            openclaw_ws_detail = {
                "note": "WS connected; RPC 'health' may be unsupported in this OpenClaw build.",
                "error": str(e),
                "type": e.__class__.__name__,
            }

    except Exception as e:
        openclaw_ws_ok = False
        openclaw_ws_detail = {"error": str(e), "type": e.__class__.__name__}

    return {
        "ok": db_ok and openclaw_ws_ok,
        "user": user.user_id,
        "db_ok": db_ok,
        "openclaw_ws_ok": openclaw_ws_ok,
        "openclaw_ws_detail": openclaw_ws_detail,
    }


@router.get(
    "/gateway/info",
    summary="Info e capabilities OpenClaw (hello-ok)",
    response_model=dict,
)
async def gateway_info(
    _: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """Ritorna l'hello del gateway (policy, methods, events).

    Utile per debug e discovery runtime.
    In caso di errore WS, ritorna 503 con dettaglio chiaro.
    """
    from app.main import get_ws_client

    ws = get_ws_client()

    try:
        hello = await ws.connect()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"OpenClaw WS connect failed: {e}")

    if hello is None:
        raise HTTPException(status_code=503, detail="OpenClaw WS connected but hello was empty.")

    return {
        "ok": True,
        "protocol": hello.protocol,
        "policy": hello.policy,
        "features": hello.features,
    }