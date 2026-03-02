from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from starlette.responses import JSONResponse, StreamingResponse

from app.core.config import settings
from app.core.openclaw_http import OpenClawHTTPError, post_json, stream_sse
from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.openai_compat import (
    ChatCompletionsRequest,
    CompletionsRequest,
    ModelsListResponse,
    OpenResponsesRequest,
)

from app.utils.sse import iter_sse_events

router = APIRouter()


# =============================================================================
# Helpers
# =============================================================================

def _agent_from_model(model: str | None) -> Optional[str]:
    """OpenClaw supports selecting agent either via model field or header.

    model: "openclaw:<agentId>" or "agent:<agentId>" (alias) or "openclaw"
    """
    if not model:
        return None
    m = str(model).strip()
    for prefix in ("openclaw:", "agent:"):
        if m.startswith(prefix):
            agent_id = m.split(":", 1)[1].strip()
            return agent_id or None
    return None


def _headers_for_openclaw(
    *,
    x_openclaw_agent_id: Optional[str],
    x_openclaw_session_key: Optional[str],
    model: Optional[str],
) -> Dict[str, str]:
    h: Dict[str, str] = {}

    # Agent routing: prefer explicit header; else infer from model; else default.
    agent = (x_openclaw_agent_id or "").strip() or (_agent_from_model(model) or "").strip() or settings.openclaw_default_agent_id
    if agent:
        h["x-openclaw-agent-id"] = agent

    # Session routing: only forward raw session key if explicitly allowed.
    if settings.allow_raw_openclaw_session_key and x_openclaw_session_key:
        h["x-openclaw-session-key"] = x_openclaw_session_key.strip()

    return h


def _http_error_from_upstream(e: OpenClawHTTPError) -> HTTPException:
    # Preserve upstream status when sensible; otherwise map to 502.
    status = e.status_code if 400 <= e.status_code < 600 else 502
    return HTTPException(status_code=status, detail=e.error)


# =============================================================================
# /v1/models
# =============================================================================

@router.get("/v1/models", response_model=ModelsListResponse, summary="List available OpenClaw agent models")
async def v1_models(user: AuthenticatedUser = Depends(get_current_user)) -> ModelsListResponse:
    # We expose a minimal list that works with OpenWebUI, etc.
    # Users can choose agent via model="openclaw:<agentId>" or header x-openclaw-agent-id.
    default_agent = settings.openclaw_default_agent_id
    data = [
        {"id": "openclaw", "object": "model", "owned_by": "openclaw"},
        {"id": f"openclaw:{default_agent}", "object": "model", "owned_by": "openclaw"},
    ]
    return ModelsListResponse(object="list", data=data)  # type: ignore[arg-type]


# =============================================================================
# /v1/chat/completions  (proxy -> OpenClaw /v1/chat/completions)
# =============================================================================

@router.post("/v1/chat/completions", summary="OpenAI-compatible Chat Completions (proxy to OpenClaw)")
async def v1_chat_completions(
    body: ChatCompletionsRequest,
    x_openclaw_session_key: Optional[str] = Header(default=None, alias="x-openclaw-session-key"),
    x_openclaw_agent_id: Optional[str] = Header(default=None, alias="x-openclaw-agent-id"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    payload = body.model_dump(mode="json", exclude_none=True)

    headers = _headers_for_openclaw(
        x_openclaw_agent_id=x_openclaw_agent_id,
        x_openclaw_session_key=x_openclaw_session_key,
        model=payload.get("model"),
    )

    stream = bool(payload.get("stream"))
    if stream:
        async def _gen():
            try:
                async for b in stream_sse("/v1/chat/completions", payload, headers=headers):
                    yield b
            except OpenClawHTTPError as e:
                # Stream-safe error: emit a single error frame then terminate.
                err = {"error": e.error}
                yield f"data: {json.dumps(err)}\n\n".encode("utf-8")
                yield b"data: [DONE]\n\n"
            except Exception as e:  # noqa: BLE001
                err = {"error": {"message": str(e), "type": "api_error"}}
                yield f"data: {json.dumps(err)}\n\n".encode("utf-8")
                yield b"data: [DONE]\n\n"

        return StreamingResponse(_gen(), media_type="text/event-stream")

    try:
        resp = await post_json("/v1/chat/completions", payload, headers=headers)
    except OpenClawHTTPError as e:
        raise _http_error_from_upstream(e)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail={"upstream": "openclaw", "message": str(e)})

    return JSONResponse(resp)


# =============================================================================
# /v1/responses (proxy -> OpenClaw /v1/responses)
# =============================================================================

@router.post("/v1/responses", summary="OpenResponses-compatible Responses (proxy to OpenClaw)")
async def v1_responses(
    body: OpenResponsesRequest,
    x_openclaw_session_key: Optional[str] = Header(default=None, alias="x-openclaw-session-key"),
    x_openclaw_agent_id: Optional[str] = Header(default=None, alias="x-openclaw-agent-id"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    payload = body.model_dump(mode="json", exclude_none=True)

    headers = _headers_for_openclaw(
        x_openclaw_agent_id=x_openclaw_agent_id,
        x_openclaw_session_key=x_openclaw_session_key,
        model=payload.get("model"),
    )

    stream = bool(payload.get("stream"))
    if stream:
        async def _gen():
            try:
                async for b in stream_sse("/v1/responses", payload, headers=headers):
                    yield b
            except OpenClawHTTPError as e:
                err = {"error": e.error}
                yield f"data: {json.dumps(err)}\n\n".encode("utf-8")
                yield b"data: [DONE]\n\n"
            except Exception as e:  # noqa: BLE001
                err = {"error": {"message": str(e), "type": "api_error"}}
                yield f"data: {json.dumps(err)}\n\n".encode("utf-8")
                yield b"data: [DONE]\n\n"

        return StreamingResponse(_gen(), media_type="text/event-stream")

    try:
        resp = await post_json("/v1/responses", payload, headers=headers)
    except OpenClawHTTPError as e:
        raise _http_error_from_upstream(e)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail={"upstream": "openclaw", "message": str(e)})

    return JSONResponse(resp)


# =============================================================================
# /v1/completions (legacy) - implemented by translating to /v1/chat/completions
# =============================================================================

def _completion_response(*, model: str, text: str, completion_id: str, created: int) -> dict:
    return {
        "id": completion_id,
        "object": "text_completion",
        "created": created,
        "model": model,
        "choices": [{"text": text, "index": 0, "logprobs": None, "finish_reason": "stop"}],
    }


def _completion_chunk(*, model: str, text: str, completion_id: str, created: int, finish_reason: str | None = None) -> dict:
    return {
        "id": completion_id,
        "object": "text_completion",
        "created": created,
        "model": model,
        "choices": [{"text": text, "index": 0, "logprobs": None, "finish_reason": finish_reason}],
    }


@router.post("/v1/completions", summary="OpenAI-compatible Completions (legacy) via Chat Completions upstream")
async def v1_completions(
    body: CompletionsRequest,
    x_openclaw_session_key: Optional[str] = Header(default=None, alias="x-openclaw-session-key"),
    x_openclaw_agent_id: Optional[str] = Header(default=None, alias="x-openclaw-agent-id"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    req = body.model_dump(mode="json", exclude_none=True)
    model = str(req.get("model") or "openclaw")
    stream = bool(req.get("stream"))

    prompt = req.get("prompt")
    if isinstance(prompt, list):
        prompt_txt = "\n\n".join(str(p) for p in prompt)
    else:
        prompt_txt = str(prompt)

    # Translate to chat.completions request
    chat_payload: Dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt_txt}],
        "stream": stream,
    }
    # best-effort carry params
    for k in ("temperature", "top_p", "max_tokens", "stop", "n", "user"):
        if k in req:
            chat_payload[k] = req[k]

    headers = _headers_for_openclaw(
        x_openclaw_agent_id=x_openclaw_agent_id,
        x_openclaw_session_key=x_openclaw_session_key,
        model=model,
    )

    if stream:
        completion_id = f"cmpl_{uuid.uuid4().hex}"
        created = int(time.time())

        async def _gen():
            try:
                async for ev in iter_sse_events(stream_sse("/v1/chat/completions", chat_payload, headers=headers)):
                    # OpenAI stream terminator
                    if ev.data.strip() == "[DONE]":
                        break
                    try:
                        chunk = json.loads(ev.data)
                    except Exception:
                        continue
                    # chat chunk -> take delta content
                    choices = chunk.get("choices") or []
                    if not choices:
                        continue
                    delta = (choices[0].get("delta") or {}).get("content")
                    finish_reason = choices[0].get("finish_reason")
                    if delta:
                        yield f"data: {json.dumps(_completion_chunk(model=model, text=str(delta), completion_id=completion_id, created=created))}\n\n".encode("utf-8")
                    if finish_reason:
                        # finish frame
                        yield f"data: {json.dumps(_completion_chunk(model=model, text='', completion_id=completion_id, created=created, finish_reason=finish_reason))}\n\n".encode("utf-8")
                        break

                yield b"data: [DONE]\n\n"
            except OpenClawHTTPError as e:
                err = {"error": e.error}
                yield f"data: {json.dumps(err)}\n\n".encode("utf-8")
                yield b"data: [DONE]\n\n"
            except Exception as e:  # noqa: BLE001
                err = {"error": {"message": str(e), "type": "api_error"}}
                yield f"data: {json.dumps(err)}\n\n".encode("utf-8")
                yield b"data: [DONE]\n\n"

        return StreamingResponse(_gen(), media_type="text/event-stream")

    try:
        resp = await post_json("/v1/chat/completions", chat_payload, headers=headers)
    except OpenClawHTTPError as e:
        raise _http_error_from_upstream(e)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail={"upstream": "openclaw", "message": str(e)})

    # Extract assistant content from chat completion
    text = ""
    try:
        choices = resp.get("choices") or []
        if choices:
            msg = choices[0].get("message") or {}
            text = msg.get("content") or ""
    except Exception:
        text = ""

    out = _completion_response(
        model=model,
        text=str(text),
        completion_id=f"cmpl_{uuid.uuid4().hex}",
        created=int(time.time()),
    )
    # Best-effort include usage if present
    if isinstance(resp, dict) and isinstance(resp.get("usage"), dict):
        out["usage"] = resp["usage"]
    return JSONResponse(out)


# =============================================================================
# /tools/invoke (proxy)
# =============================================================================

@router.post("/tools/invoke", summary="Proxy to OpenClaw /tools/invoke")
async def tools_invoke(
    payload: Dict[str, Any],
    x_openclaw_agent_id: Optional[str] = Header(default=None, alias="x-openclaw-agent-id"),
    x_openclaw_session_key: Optional[str] = Header(default=None, alias="x-openclaw-session-key"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    headers = _headers_for_openclaw(
        x_openclaw_agent_id=x_openclaw_agent_id,
        x_openclaw_session_key=x_openclaw_session_key,
        model=str(payload.get("model") or ""),
    )

    try:
        resp = await post_json("/tools/invoke", payload, headers=headers)
    except OpenClawHTTPError as e:
        raise _http_error_from_upstream(e)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail={"upstream": "openclaw", "message": str(e)})

    return JSONResponse(resp)
