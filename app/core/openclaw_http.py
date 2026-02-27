"""
Client HTTP verso OpenClaw Gateway.

Supporta:
- POST JSON (OpenResponses / ChatCompletions)
- streaming SSE (OpenResponses / ChatCompletions)

Nota importante:
- NON usare raise_for_status() in modo "cieco", altrimenti un 400/401/500 di OpenClaw
  diventa un 500 FastAPI del BFF (stacktrace), rendendo impossibile il debug lato FE.
- Questo modulo espone OpenClawHTTPError con status+body per:
  1) mostrare dettagli upstream al FE (come 502)
  2) implementare fallback automatico (es. se input structured non è supportato)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, AsyncGenerator, Dict, Optional

import httpx

from app.core.config import settings


def _auth_headers() -> Dict[str, str]:
    h: Dict[str, str] = {}
    if settings.openclaw_bearer_token:
        h["Authorization"] = f"Bearer {settings.openclaw_bearer_token}"
    return h


def _full_url(path: str) -> str:
    return settings.openclaw_http_base.rstrip("/") + path


def _safe_json(resp: httpx.Response) -> Dict[str, Any]:
    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text}


def is_invalid_input_error(err_json: Dict[str, Any]) -> bool:
    """
    Riconosce l'errore tipico:
      {"error":{"message":"input: Invalid input","type":"invalid_request_error"}}
    """
    err = err_json.get("error")
    if not isinstance(err, dict):
        return False
    msg = (err.get("message") or "") if isinstance(err.get("message"), str) else ""
    typ = (err.get("type") or "") if isinstance(err.get("type"), str) else ""
    return ("Invalid input" in msg) and (typ in ("invalid_request_error", "invalid_request"))


@dataclass
class OpenClawHTTPError(Exception):
    """
    Errore upstream OpenClaw.

    Contiene:
    - status_code: status HTTP da OpenClaw
    - url: URL chiamata
    - error: body JSON (o {"raw": ...})
    """

    status_code: int
    url: str
    error: Dict[str, Any]

    def __str__(self) -> str:
        return f"OpenClawHTTPError(status={self.status_code}, url={self.url}, error={self.error})"


async def post_json(
    path: str,
    payload: dict,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 60.0,
) -> dict:
    """
    POST JSON verso OpenClaw.

    Solleva OpenClawHTTPError se status >= 400 (con body).
    """
    url = _full_url(path)
    h = {**_auth_headers(), **(headers or {})}

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json=payload, headers=h)

    if resp.status_code >= 400:
        raise OpenClawHTTPError(status_code=resp.status_code, url=url, error=_safe_json(resp))

    return resp.json()


async def stream_sse(
    path: str,
    payload: dict,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 600.0,
) -> AsyncGenerator[bytes, None]:
    """
    POST che risponde con SSE. Ritorna i bytes grezzi.

    Se OpenClaw risponde errore (>=400), solleva OpenClawHTTPError (con body).
    """
    url = _full_url(path)
    h = {
        **_auth_headers(),
        "Accept": "text/event-stream",
        **(headers or {}),
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        async with client.stream("POST", url, json=payload, headers=h) as resp:
            if resp.status_code >= 400:
                # Leggi tutto il body (se json) prima di alzare errore
                body_bytes = await resp.aread()
                try:
                    err = httpx.Response(
                        status_code=resp.status_code,
                        headers=resp.headers,
                        content=body_bytes,
                        request=resp.request,
                    ).json()
                except Exception:
                    err = {"raw": body_bytes.decode("utf-8", errors="replace")}
                raise OpenClawHTTPError(status_code=resp.status_code, url=url, error=err)

            async for chunk in resp.aiter_bytes():
                yield chunk