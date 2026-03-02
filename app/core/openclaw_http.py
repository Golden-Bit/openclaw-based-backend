"""
Client HTTP verso OpenClaw Gateway.

Supporta:
- POST JSON
- streaming SSE (OpenResponses / ChatCompletions)

MIGLIORIA CHIAVE:
- NON usare resp.raise_for_status() senza leggere il body: un 400 upstream diventa un 500 “muto”.
- Solleva OpenClawHTTPError con status/url/body JSON (best-effort).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, AsyncGenerator, Dict, Optional

import httpx

from app.core.config import settings


@dataclass
class OpenClawHTTPError(RuntimeError):
    status_code: int
    url: str
    error: Any

    def __str__(self) -> str:
        return f"OpenClawHTTPError(status={self.status_code}, url={self.url}, error={self.error})"


def is_invalid_input_error(err: Any) -> bool:
    """
    Best-effort: riconosce il classico errore OpenClaw/OpenAI compat:
      {"error":{"message":"input: Invalid input","type":"invalid_request_error"}}
    """
    if not isinstance(err, dict):
        return False
    e = err.get("error")
    if isinstance(e, dict):
        msg = str(e.get("message") or "")
        typ = str(e.get("type") or "")
        return "Invalid input" in msg and "invalid_request_error" in typ
    return False


def _auth_headers() -> Dict[str, str]:
    h: Dict[str, str] = {}
    if settings.openclaw_bearer_token:
        h["Authorization"] = f"Bearer {settings.openclaw_bearer_token}"
    return h


async def post_json(
    path: str,
    payload: dict,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 60.0,
) -> dict:
    url = settings.openclaw_http_base.rstrip("/") + path
    h = {**_auth_headers(), **(headers or {})}

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json=payload, headers=h)

    if resp.status_code >= 400:
        try:
            err = resp.json()
        except Exception:
            err = {"raw": resp.text}
        raise OpenClawHTTPError(status_code=resp.status_code, url=url, error=err)

    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text}


async def stream_sse(
    path: str,
    payload: dict,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 600.0,
) -> AsyncGenerator[bytes, None]:
    """
    Esegue una POST che risponde con SSE e restituisce i bytes grezzi.
    Se upstream risponde con errore, solleva OpenClawHTTPError (con body).
    """
    url = settings.openclaw_http_base.rstrip("/") + path
    h = {
        **_auth_headers(),
        "Accept": "text/event-stream",
        **(headers or {}),
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        async with client.stream("POST", url, json=payload, headers=h) as resp:
            if resp.status_code >= 400:
                try:
                    err = await resp.json()
                except Exception:
                    err = {"raw": await resp.aread()}
                raise OpenClawHTTPError(status_code=resp.status_code, url=url, error=err)

            async for chunk in resp.aiter_bytes():
                yield chunk