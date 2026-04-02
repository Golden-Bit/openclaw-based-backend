from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.config import settings
from app.core.openclaw_ws import OpenClawWSClient
from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.agents import (
    AgentDeleteResponse,
    AgentDetailResponse,
    AgentListResponse,
    AgentSummary,
    AgentUpdateRequest,
    AgentUpdateResponse,
)

router = APIRouter(prefix="/agents")

_agents_ws_client: OpenClawWSClient | None = None


def _is_method_unsupported(error_text: str) -> bool:
    t = error_text.lower()
    return (
        "method_not_found" in t
        or "method not found" in t
        or "unknown method" in t
        or "not implemented" in t
    )


def _map_ws_error(method: str, exc: Exception, *, not_found_agent_id: Optional[str] = None) -> HTTPException:
    msg = str(exc)
    lower = msg.lower()

    if _is_method_unsupported(lower):
        return HTTPException(status_code=501, detail=f"OpenClaw WS method '{method}' unsupported: {msg}")

    if "missing scope" in lower or "forbidden" in lower or "unauthorized" in lower:
        return HTTPException(
            status_code=503,
            detail=f"OpenClaw WS authorization failed for '{method}': {msg}",
        )

    if "timeout" in lower:
        return HTTPException(status_code=504, detail=f"OpenClaw WS timeout on '{method}': {msg}")

    if not_found_agent_id and "not found" in lower:
        return HTTPException(status_code=404, detail=f"Agent '{not_found_agent_id}' not found")

    if "invalid request" in lower or "invalid" in lower:
        return HTTPException(status_code=400, detail=f"Invalid request for '{method}': {msg}")

    return HTTPException(status_code=502, detail=f"OpenClaw WS '{method}' failed: {msg}")


async def _get_connected_ws():
    global _agents_ws_client
    if _agents_ws_client is None:
        _agents_ws_client = OpenClawWSClient(settings.openclaw_ws_url)

    ws = _agents_ws_client
    try:
        _ = await ws.connect()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"OpenClaw WS connect failed: {e}")
    return ws


def _normalize_agent_summary(raw: Dict[str, Any], *, default_agent_id: str) -> AgentSummary:
    model_raw = raw.get("model")

    model: Optional[str] = None
    model_fallbacks: Optional[List[str]] = None

    if isinstance(model_raw, dict):
        primary = model_raw.get("primary")
        if isinstance(primary, str) and primary.strip():
            model = primary.strip()

        fbs = model_raw.get("fallbacks")
        if isinstance(fbs, list):
            cleaned = [str(x).strip() for x in fbs if str(x).strip()]
            model_fallbacks = cleaned or None

    agent_id = str(raw.get("id") or "").strip()
    name = raw.get("name")
    workspace = raw.get("workspace")

    return AgentSummary(
        agent_id=agent_id,
        name=(str(name).strip() if isinstance(name, str) and name.strip() else None),
        workspace=(str(workspace).strip() if isinstance(workspace, str) and workspace.strip() else None),
        model=model,
        model_fallbacks=model_fallbacks,
        is_default=(agent_id == default_agent_id),
    )


def _find_agent(raw_agents: list[Any], agent_id: str) -> Optional[Dict[str, Any]]:
    for item in raw_agents:
        if isinstance(item, dict) and str(item.get("id") or "").strip() == agent_id:
            return item

    # best-effort case-insensitive fallback
    lowered = agent_id.lower()
    for item in raw_agents:
        if isinstance(item, dict) and str(item.get("id") or "").strip().lower() == lowered:
            return item
    return None


@router.get(
    "",
    summary="Lista agenti OpenClaw",
    response_model=AgentListResponse,
)
async def list_agents(
    _: AuthenticatedUser = Depends(get_current_user),
) -> AgentListResponse:
    ws = await _get_connected_ws()

    try:
        payload = await ws.call("agents.list", {})
    except Exception as e:  # noqa: BLE001
        raise _map_ws_error("agents.list", e)

    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail=f"Unexpected OpenClaw payload for agents.list: {payload!r}")

    default_agent_id = str(payload.get("defaultId") or settings.openclaw_default_agent_id)
    main_key_raw = payload.get("mainKey")
    scope_raw = payload.get("scope")

    raw_agents = payload.get("agents")
    if not isinstance(raw_agents, list):
        raw_agents = []

    items = [
        _normalize_agent_summary(agent, default_agent_id=default_agent_id)
        for agent in raw_agents
        if isinstance(agent, dict)
    ]

    return AgentListResponse(
        default_agent_id=default_agent_id,
        main_key=(str(main_key_raw).strip() if isinstance(main_key_raw, str) and main_key_raw.strip() else None),
        scope=(str(scope_raw).strip() if isinstance(scope_raw, str) and scope_raw.strip() else None),
        items=items,
    )


@router.get(
    "/{agent_id}",
    summary="Dettaglio agente OpenClaw",
    response_model=AgentDetailResponse,
)
async def get_agent(
    agent_id: str,
    include_files: bool = Query(default=False, description="Se true include agents.files.list"),
    _: AuthenticatedUser = Depends(get_current_user),
) -> AgentDetailResponse:
    agent_id = (agent_id or "").strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")

    ws = await _get_connected_ws()

    try:
        list_payload = await ws.call("agents.list", {})
    except Exception as e:  # noqa: BLE001
        raise _map_ws_error("agents.list", e)

    if not isinstance(list_payload, dict):
        raise HTTPException(status_code=502, detail=f"Unexpected OpenClaw payload for agents.list: {list_payload!r}")

    raw_agents = list_payload.get("agents")
    if not isinstance(raw_agents, list):
        raw_agents = []

    selected = _find_agent(raw_agents, agent_id)
    if selected is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    default_agent_id = str(list_payload.get("defaultId") or settings.openclaw_default_agent_id)
    summary = _normalize_agent_summary(selected, default_agent_id=default_agent_id)

    warnings: list[str] = []
    identity: Optional[Dict[str, Any]] = None
    files: Optional[List[Dict[str, Any]]] = None

    # identity (best-effort)
    try:
        identity_payload = await ws.call("agent.identity.get", {"agentId": summary.agent_id})
        if isinstance(identity_payload, dict):
            normalized_identity = dict(identity_payload)
            if "agentId" in normalized_identity and "agent_id" not in normalized_identity:
                normalized_identity["agent_id"] = normalized_identity.pop("agentId")
            if "avatarUrl" in normalized_identity and "avatar_url" not in normalized_identity:
                normalized_identity["avatar_url"] = normalized_identity.pop("avatarUrl")
            identity = normalized_identity
        else:
            identity = {"payload": identity_payload}
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        if _is_method_unsupported(msg):
            warnings.append("OpenClaw method 'agent.identity.get' unsupported by gateway build")
        elif "not found" in msg.lower():
            raise HTTPException(status_code=404, detail=f"Agent '{summary.agent_id}' not found")
        else:
            warnings.append(f"agent.identity.get failed: {msg}")

    # files (optional, best-effort)
    if include_files:
        try:
            files_payload = await ws.call("agents.files.list", {"agentId": summary.agent_id})
            if isinstance(files_payload, dict):
                raw_files = files_payload.get("files")
                if isinstance(raw_files, list):
                    files = [f for f in raw_files if isinstance(f, dict)]
                else:
                    files = []
            elif isinstance(files_payload, list):
                files = [f for f in files_payload if isinstance(f, dict)]
            else:
                files = [{"payload": files_payload}]
        except Exception as e:  # noqa: BLE001
            msg = str(e)
            if _is_method_unsupported(msg):
                warnings.append("OpenClaw method 'agents.files.list' unsupported by gateway build")
            elif "not found" in msg.lower():
                raise HTTPException(status_code=404, detail=f"Agent '{summary.agent_id}' not found")
            else:
                warnings.append(f"agents.files.list failed: {msg}")

    return AgentDetailResponse(
        **summary.model_dump(),
        identity=identity,
        files=files,
        warnings=warnings,
    )


@router.patch(
    "/{agent_id}",
    summary="Modifica agente OpenClaw",
    response_model=AgentUpdateResponse,
)
async def update_agent(
    agent_id: str,
    body: AgentUpdateRequest,
    _: AuthenticatedUser = Depends(get_current_user),
) -> AgentUpdateResponse:
    agent_id = (agent_id or "").strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")

    params: Dict[str, Any] = {"agentId": agent_id}

    if body.name is not None:
        name = body.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="name cannot be empty")
        params["name"] = name

    if body.workspace is not None:
        workspace = body.workspace.strip()
        if not workspace:
            raise HTTPException(status_code=400, detail="workspace cannot be empty")
        params["workspace"] = workspace

    if body.model is not None:
        model = body.model.strip()
        if not model:
            raise HTTPException(status_code=400, detail="model cannot be empty")
        params["model"] = model

    if body.avatar is not None:
        avatar = body.avatar.strip()
        if not avatar:
            raise HTTPException(status_code=400, detail="avatar cannot be empty")
        params["avatar"] = avatar

    if len(params) == 1:
        raise HTTPException(status_code=400, detail="At least one field among name/workspace/model/avatar is required")

    ws = await _get_connected_ws()

    try:
        res = await ws.call("agents.update", params)
    except Exception as e:  # noqa: BLE001
        raise _map_ws_error("agents.update", e, not_found_agent_id=agent_id)

    return AgentUpdateResponse(
        updated=True,
        agent_id=agent_id,
        openclaw_result=(res if isinstance(res, dict) else {"payload": res}),
    )


@router.delete(
    "/{agent_id}",
    summary="Elimina agente OpenClaw",
    response_model=AgentDeleteResponse,
)
async def delete_agent(
    agent_id: str,
    delete_files: bool = Query(default=True, description="Propagato a OpenClaw come deleteFiles"),
    _: AuthenticatedUser = Depends(get_current_user),
) -> AgentDeleteResponse:
    agent_id = (agent_id or "").strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")

    ws = await _get_connected_ws()

    try:
        res = await ws.call("agents.delete", {"agentId": agent_id, "deleteFiles": delete_files})
    except Exception as e:  # noqa: BLE001
        raise _map_ws_error("agents.delete", e, not_found_agent_id=agent_id)

    removed_bindings: Optional[int] = None
    if isinstance(res, dict):
        rb = res.get("removedBindings")
        if isinstance(rb, int):
            removed_bindings = rb

    return AgentDeleteResponse(
        deleted=True,
        agent_id=agent_id,
        removed_bindings=removed_bindings,
        openclaw_result=(res if isinstance(res, dict) else {"payload": res}),
    )
