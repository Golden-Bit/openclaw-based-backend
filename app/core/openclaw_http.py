"""Client HTTP verso OpenClaw Gateway.

Supporta:
- POST JSON
- streaming SSE (OpenResponses / ChatCompletions)

Nota: OpenClaw richiede header `Authorization: Bearer <token>` se configurato.
"""

from __future__ import annotations

from typing import Any, AsyncGenerator, Dict, Optional

import httpx

from app.core.config import settings


def _auth_headers() -> Dict[str, str]:
    h: Dict[str, str] = {}
    if settings.openclaw_bearer_token:
        h["Authorization"] = f"Bearer {settings.openclaw_bearer_token}"
    return h


async def post_json(path: str, payload: dict, headers: Optional[Dict[str, str]] = None, timeout: float = 60.0) -> dict:
    url = settings.openclaw_http_base.rstrip("/") + path
    h = {**_auth_headers(), **(headers or {})}
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json=payload, headers=h)
        resp.raise_for_status()
        return resp.json()


async def stream_sse(
    path: str,
    payload: dict,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 600.0,
) -> AsyncGenerator[bytes, None]:
    """Esegue una POST che risponde con SSE e restituisce i bytes grezzi."""

    url = settings.openclaw_http_base.rstrip("/") + path
    h = {
        **_auth_headers(),
        "Accept": "text/event-stream",
        **(headers or {}),
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        async with client.stream("POST", url, json=payload, headers=h) as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                yield chunk
