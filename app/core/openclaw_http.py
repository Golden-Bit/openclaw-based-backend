"""Client HTTP verso OpenClaw Gateway.

Questo client viene usato per gli endpoint HTTP OpenAI-compatibili esposti dal gateway
(es. /v1/responses) e per eventuale streaming SSE.

Nota importante:
- Non bisogna chiamare `raise_for_status()` senza prima leggere il body.
  Altrimenti gli errori upstream (400/401/500) diventano stacktrace 500 nel BFF.
  Invece, qui convertiamo gli errori in una eccezione strutturata `OpenClawHTTPError`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, AsyncGenerator, Dict, Optional

import httpx
import os

from app.core.config import settings


def _auth_headers() -> Dict[str, str]:
    h: Dict[str, str] = {}
    # Compat: supporta sia OPENCLAW_GATEWAY_TOKEN (Settings) sia OPENCLAW_BEARER_TOKEN
    bearer = settings.openclaw_bearer_token or os.getenv("OPENCLAW_BEARER_TOKEN")
    if bearer:
        h["Authorization"] = f"Bearer {bearer}"
    return h


@dataclass
class OpenClawHTTPError(Exception):
    """Errore HTTP upstream da OpenClaw."""

    status_code: int
    url: str
    error: Any


def is_invalid_input_error(err: Any) -> bool:
    """Rileva il classico errore OpenAI/OpenResponses: input invalid."""

    if not isinstance(err, dict):
        return False
    payload = err.get("error") if "error" in err else err
    if not isinstance(payload, dict):
        return False

    msg = str(payload.get("message") or "").lower()
    typ = str(payload.get("type") or "").lower()
    return ("invalid input" in msg) or ("invalid_request" in typ and "input" in msg)


async def post_json(
    path: str,
    payload: dict,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 60.0,
) -> dict:
    """POST JSON verso OpenClaw.

    Ritorna JSON dict.
    Se status >= 400 solleva OpenClawHTTPError con body parseato (se possibile).
    """

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

    return resp.json()


async def stream_sse(
    path: str,
    payload: dict,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 600.0,
) -> AsyncGenerator[bytes, None]:
    """POST che risponde con SSE; restituisce i bytes grezzi.

    Se OpenClaw risponde con status >= 400, solleva OpenClawHTTPError.
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
                    err_bytes = await resp.aread()
                    try:
                        err_json = httpx.Response(200, content=err_bytes).json()
                    except Exception:
                        err_json = {"raw": err_bytes.decode("utf-8", errors="replace")}
                except Exception:
                    err_json = {"raw": "<unable to read body>"}
                raise OpenClawHTTPError(status_code=resp.status_code, url=url, error=err_json)

            async for chunk in resp.aiter_bytes():
                yield chunk
