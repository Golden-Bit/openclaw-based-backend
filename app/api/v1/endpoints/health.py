from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends
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

    - `db_ok`: verifica semplice query `SELECT 1`
    - `openclaw_ws_ok`: tenta connessione WS e call `health` se possibile
    """

    # DB
    db_ok = True
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_ok = False

    # OpenClaw WS (best-effort)
    openclaw_ws_ok = False
    openclaw_ws_detail: Optional[dict] = None
    try:
        from app.main import get_ws_client

        ws = get_ws_client()
        await ws.connect()
        # Non tutti i gateway hanno metodo health su WS; best-effort
        try:
            openclaw_ws_detail = await ws.call("health", {})
        except Exception:
            openclaw_ws_detail = None
        openclaw_ws_ok = True
    except Exception:
        openclaw_ws_ok = False

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
    """
    from app.main import get_ws_client

    ws = get_ws_client()
    hello = await ws.connect()
    return {
        "protocol": hello.protocol,
        "policy": hello.policy,
        "features": hello.features,
    }
