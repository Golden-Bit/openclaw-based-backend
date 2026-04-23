from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.agent_ownership import (
    build_user_scoped_agent_id,
    is_agent_id_owned_by_user,
    is_workspace_owned_by_user,
    normalize_workspace_for_user,
    resolve_requested_agent_id_for_user,
    user_agent_id_prefix,
    user_workspace_bases,
)
from app.core.agent_share_skill import ensure_share_skill_for_agent
from app.core.config import settings
from app.core.openclaw_ws import OpenClawWSClient
from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.agents import (
    AgentCreateRequest,
    AgentCreateResponse,
    AgentDeleteResponse,
    AgentDetailResponse,
    AgentListResponse,
    AgentSummary,
    AgentUpdateRequest,
    AgentUpdateResponse,
)

router = APIRouter(prefix="/agents")

_agents_ws_client: OpenClawWSClient | None = None
logger = logging.getLogger(__name__)


def _workspace_bases_as_posix(user_id: str) -> list[str]:
    return [base.as_posix() for base in user_workspace_bases(user_id)]


def _resolve_requested_agent_id_or_400(user: AuthenticatedUser, requested_agent_id: str) -> str:
    raw = (requested_agent_id or "").strip().lower()
    if not raw:
        raise HTTPException(status_code=400, detail="agent_id is required")
    return raw


def _candidate_agent_ids_for_request(user: AuthenticatedUser, requested_agent_id: str) -> list[str]:
    resolved_raw = _resolve_requested_agent_id_or_400(user, requested_agent_id)
    candidates = [resolved_raw]
    try:
        scoped = resolve_requested_agent_id_for_user(user.user_id, resolved_raw)
        if scoped not in candidates:
            candidates.append(scoped)
    except ValueError:
        pass
    return candidates


def _log_agents_list_raw(*, context: str, payload: Any) -> None:
    logger.info("agents.list raw context=%s payload=%r", context, payload)


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


def _friendly_agent_name_for_user(user_id: str | None, raw_name: Any, agent_id: str) -> Optional[str]:
    name: Optional[str] = str(raw_name).strip() if isinstance(raw_name, str) and str(raw_name).strip() else None
    if not user_id:
        return name

    prefix = f"{user_agent_id_prefix(user_id)}-"
    if name and name.lower().startswith(prefix):
        trimmed = name[len(prefix) :].strip()
        if trimmed:
            return trimmed

    if (not name) and agent_id and agent_id.lower().startswith(prefix):
        trimmed = agent_id[len(prefix) :].strip()
        if trimmed:
            return trimmed

    return name


def _normalize_agent_summary(raw: Dict[str, Any], *, default_agent_id: str, user_id: str | None = None) -> AgentSummary:
    model_raw = raw.get("model")
    identity_raw = raw.get("identity")

    model: Optional[str] = None
    model_fallbacks: Optional[List[str]] = None

    if isinstance(model_raw, str) and model_raw.strip():
        model = model_raw.strip()
    elif isinstance(model_raw, dict):
        primary = model_raw.get("primary")
        if isinstance(primary, str) and primary.strip():
            model = primary.strip()

        fbs = model_raw.get("fallbacks")
        if isinstance(fbs, list):
            cleaned = [str(x).strip() for x in fbs if str(x).strip()]
            model_fallbacks = cleaned or None

    agent_id = str(raw.get("id") or "").strip().lower()
    name_raw = raw.get("name")
    if (not isinstance(name_raw, str) or not name_raw.strip()) and isinstance(identity_raw, dict):
        name_raw = identity_raw.get("name")
    workspace = raw.get("workspace")
    display_name = _friendly_agent_name_for_user(user_id, name_raw, agent_id)

    return AgentSummary(
        agent_id=agent_id,
        name=display_name,
        workspace=(str(workspace).strip() if isinstance(workspace, str) and workspace.strip() else None),
        model=model,
        model_fallbacks=model_fallbacks,
        is_default=(agent_id == default_agent_id),
    )


def _workspace_from_raw_agent(raw: Dict[str, Any]) -> Optional[str]:
    workspace = raw.get("workspace")
    if isinstance(workspace, str) and workspace.strip():
        return workspace.strip()
    return None


async def _workspace_from_files_list(ws, agent_id: str) -> Optional[str]:
    if not agent_id:
        return None
    try:
        files_payload = await ws.call("agents.files.list", {"agentId": agent_id})
    except Exception as e:  # noqa: BLE001
        logger.info("agents.workspace resolve via files.list failed agent_id=%s error=%s", agent_id, e)
        return None
    if isinstance(files_payload, dict):
        workspace = files_payload.get("workspace")
        if isinstance(workspace, str) and workspace.strip():
            return workspace.strip()
    return None


async def _resolve_agent_ownership(ws, user: AuthenticatedUser, raw_agent: Dict[str, Any]) -> tuple[str, Optional[str], bool, bool, bool]:
    selected_agent_id = str(raw_agent.get("id") or "").strip().lower()
    workspace = _workspace_from_raw_agent(raw_agent)
    owned_by_id = is_agent_id_owned_by_user(user.user_id, selected_agent_id)
    if not workspace and selected_agent_id:
        workspace = await _workspace_from_files_list(ws, selected_agent_id)
    owned_by_workspace = is_workspace_owned_by_user(user.user_id, workspace)
    allowed = owned_by_id or owned_by_workspace
    return selected_agent_id, workspace, owned_by_id, owned_by_workspace, allowed


async def _enforce_agent_ownership_or_404(
    ws,
    user: AuthenticatedUser,
    raw_agent: Dict[str, Any],
    *,
    requested_agent_id: str,
) -> tuple[str, Optional[str]]:
    selected_agent_id, workspace, owned_by_id, owned_by_workspace, allowed = await _resolve_agent_ownership(ws, user, raw_agent)

    if not allowed:
        logger.warning(
            (
                "agents.ownership denied user_id=%s requested_agent_id=%s selected_agent_id=%s "
                "workspace=%s expected_agent_prefix=%s owned_by_id=%s owned_by_workspace=%s"
            ),
            user.user_id,
            requested_agent_id,
            selected_agent_id or None,
            workspace,
            user_agent_id_prefix(user.user_id),
            owned_by_id,
            owned_by_workspace,
        )
        raise HTTPException(status_code=404, detail=f"Agent '{requested_agent_id}' not found")
    return selected_agent_id, workspace


async def _get_owned_agent_or_404(ws, user: AuthenticatedUser, agent_id: str) -> Dict[str, Any]:
    candidate_ids = _candidate_agent_ids_for_request(user, agent_id)
    resolved_agent_id = candidate_ids[0]

    try:
        list_payload = await ws.call("agents.list", {})
    except Exception as e:  # noqa: BLE001
        raise _map_ws_error("agents.list", e, not_found_agent_id=resolved_agent_id)

    _log_agents_list_raw(context="owned_agent_lookup", payload=list_payload)

    if not isinstance(list_payload, dict):
        raise HTTPException(status_code=502, detail=f"Unexpected OpenClaw payload for agents.list: {list_payload!r}")

    raw_agents = list_payload.get("agents")
    if not isinstance(raw_agents, list):
        raw_agents = []

    selected = None
    for candidate_id in candidate_ids:
        selected = _find_agent(raw_agents, candidate_id)
        if selected is not None:
            break

    if selected is None:
        raise HTTPException(status_code=404, detail=f"Agent '{resolved_agent_id}' not found")

    await _enforce_agent_ownership_or_404(ws, user, selected, requested_agent_id=resolved_agent_id)
    return selected


@router.post(
    "",
    summary="Crea agente OpenClaw",
    response_model=AgentCreateResponse,
)
async def create_agent(
    body: AgentCreateRequest,
    user: AuthenticatedUser = Depends(get_current_user),
) -> AgentCreateResponse:
    requested_agent_token = body.name.strip()
    workspace_input = body.workspace.strip()

    if not requested_agent_token:
        raise HTTPException(status_code=400, detail="name cannot be empty")
    if not workspace_input:
        raise HTTPException(status_code=400, detail="workspace cannot be empty")

    scoped_agent_id = build_user_scoped_agent_id(user.user_id, requested_agent_token)

    try:
        workspace = normalize_workspace_for_user(user.user_id, workspace_input)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))

    params: Dict[str, Any] = {
        # Use scoped agent id as OpenClaw logical id to avoid cross-user collisions
        # when different users create same display name (e.g. "default").
        "name": scoped_agent_id,
        "workspace": workspace,
    }

    if body.emoji is not None:
        emoji = body.emoji.strip()
        if not emoji:
            raise HTTPException(status_code=400, detail="emoji cannot be empty")
        params["emoji"] = emoji

    if body.avatar is not None:
        avatar = body.avatar.strip()
        if not avatar:
            raise HTTPException(status_code=400, detail="avatar cannot be empty")
        params["avatar"] = avatar

    ws = await _get_connected_ws()

    try:
        res = await ws.call("agents.create", params)
    except Exception as e:  # noqa: BLE001
        raise _map_ws_error("agents.create", e)

    agent_id: Optional[str] = None
    result_name: Optional[str] = requested_agent_token
    result_workspace: Optional[str] = workspace

    if isinstance(res, dict):
        rid = res.get("agentId")
        if isinstance(rid, str) and rid.strip():
            agent_id = rid.strip().lower()

        rworkspace = res.get("workspace")
        if isinstance(rworkspace, str) and rworkspace.strip():
            result_workspace = rworkspace.strip()

    if not agent_id:
        agent_id = scoped_agent_id

    owned_by_id = is_agent_id_owned_by_user(user.user_id, agent_id)
    owned_by_workspace = is_workspace_owned_by_user(user.user_id, result_workspace)
    if not (owned_by_id or owned_by_workspace):
        rollback_error: Optional[Exception] = None
        try:
            _ = await ws.call("agents.delete", {"agentId": agent_id, "deleteFiles": True})
        except Exception as e:  # noqa: BLE001
            rollback_error = e

        if rollback_error is None:
            raise HTTPException(
                status_code=502,
                detail=(
                    f"OpenClaw returned non-owned agent_id '{agent_id}' for user '{user.user_id}'. "
                    f"(owned_by_id={owned_by_id}, owned_by_workspace={owned_by_workspace}) "
                    "Agent create was rolled back."
                ),
            )
        raise HTTPException(
            status_code=502,
            detail=(
                f"OpenClaw returned non-owned agent_id '{agent_id}' "
                f"(owned_by_id={owned_by_id}, owned_by_workspace={owned_by_workspace}) "
                f"and rollback failed: {rollback_error}"
            ),
        )

    effective_workspace = result_workspace or workspace
    expected_bases = _workspace_bases_as_posix(user.user_id)
    effective_owned = is_workspace_owned_by_user(user.user_id, effective_workspace)

    logger.info(
        (
            "agents.create ownership context user_id=%s requested_agent_token=%s scoped_agent_id=%s "
            "input_workspace=%s normalized_workspace=%s gateway_workspace=%s effective_workspace=%s "
            "expected_bases=%s owned_effective=%s agent_id=%s"
        ),
        user.user_id,
        requested_agent_token,
        scoped_agent_id,
        workspace_input,
        workspace,
        result_workspace,
        effective_workspace,
        expected_bases,
        effective_owned,
        agent_id,
    )

    try:
        skill_path = ensure_share_skill_for_agent(effective_workspace, user_id=user.user_id)
        logger.info(
            (
                "agents.create share_skill bootstrap success user_id=%s agent_id=%s "
                "effective_workspace=%s skill_file=%s"
            ),
            user.user_id,
            agent_id,
            effective_workspace,
            skill_path.as_posix(),
        )
    except Exception as skill_err:  # noqa: BLE001
        expected_skill_path = f"{effective_workspace.rstrip('/')}/skills/share-files/SKILL.md"
        logger.exception(
            (
                "agents.create share_skill bootstrap failed user_id=%s agent_id=%s "
                "effective_workspace=%s expected_skill_file=%s"
            ),
            user.user_id,
            agent_id,
            effective_workspace,
            expected_skill_path,
        )

        rollback_error: Optional[Exception] = None
        if agent_id:
            try:
                _ = await ws.call("agents.delete", {"agentId": agent_id, "deleteFiles": True})
            except Exception as e:  # noqa: BLE001
                rollback_error = e

        if rollback_error is None:
            raise HTTPException(
                status_code=500,
                detail=f"Agent created but share skill bootstrap failed; create was rolled back: {skill_err}",
            )

        raise HTTPException(
            status_code=500,
            detail=(
                "Agent created but share skill bootstrap failed and rollback failed: "
                f"bootstrap_error={skill_err}; rollback_error={rollback_error}"
            ),
        )

    return AgentCreateResponse(
        created=True,
        agent_id=agent_id,
        name=result_name,
        workspace=result_workspace,
        openclaw_result=(res if isinstance(res, dict) else {"payload": res}),
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
    user: AuthenticatedUser = Depends(get_current_user),
) -> AgentListResponse:
    ws = await _get_connected_ws()

    try:
        payload = await ws.call("agents.list", {})
    except Exception as e:  # noqa: BLE001
        raise _map_ws_error("agents.list", e)

    _log_agents_list_raw(context="list_agents", payload=payload)

    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail=f"Unexpected OpenClaw payload for agents.list: {payload!r}")

    default_agent_id = str(payload.get("defaultId") or settings.openclaw_default_agent_id)
    main_key_raw = payload.get("mainKey")
    scope_raw = payload.get("scope")

    raw_agents = payload.get("agents")
    if not isinstance(raw_agents, list):
        raw_agents = []

    expected_agent_prefix = user_agent_id_prefix(user.user_id)
    items: list[AgentSummary] = []
    for agent in raw_agents:
        if not isinstance(agent, dict):
            continue

        selected_agent_id, resolved_workspace, owned_by_id, owned_by_workspace, allowed = await _resolve_agent_ownership(
            ws,
            user,
            agent,
        )

        logger.info(
            (
                "agents.list ownership check user_id=%s agent_id=%s workspace=%s "
                "expected_agent_prefix=%s owned_by_id=%s owned_by_workspace=%s allowed=%s"
            ),
            user.user_id,
            selected_agent_id or None,
            resolved_workspace,
            expected_agent_prefix,
            owned_by_id,
            owned_by_workspace,
            allowed,
        )

        if not allowed:
            continue
        items.append(
            _normalize_agent_summary(
                {
                    **agent,
                    "workspace": resolved_workspace if resolved_workspace else agent.get("workspace"),
                },
                default_agent_id=default_agent_id,
                user_id=user.user_id,
            )
        )

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
    user: AuthenticatedUser = Depends(get_current_user),
) -> AgentDetailResponse:
    candidate_ids = _candidate_agent_ids_for_request(user, agent_id)
    requested_agent_id = candidate_ids[0]

    ws = await _get_connected_ws()

    try:
        list_payload = await ws.call("agents.list", {})
    except Exception as e:  # noqa: BLE001
        raise _map_ws_error("agents.list", e)

    _log_agents_list_raw(context="get_agent", payload=list_payload)

    if not isinstance(list_payload, dict):
        raise HTTPException(status_code=502, detail=f"Unexpected OpenClaw payload for agents.list: {list_payload!r}")

    raw_agents = list_payload.get("agents")
    if not isinstance(raw_agents, list):
        raw_agents = []

    selected = None
    for candidate_id in candidate_ids:
        selected = _find_agent(raw_agents, candidate_id)
        if selected is not None:
            break

    if selected is None:
        raise HTTPException(status_code=404, detail=f"Agent '{requested_agent_id}' not found")

    selected_agent_id, selected_workspace, selected_owned_by_id, selected_owned_by_workspace, selected_allowed = (
        await _resolve_agent_ownership(ws, user, selected)
    )
    expected_agent_prefix = user_agent_id_prefix(user.user_id)

    logger.info(
        (
            "agents.get ownership check user_id=%s requested_agent_id=%s selected_agent_id=%s "
            "workspace=%s expected_agent_prefix=%s owned_by_id=%s owned_by_workspace=%s allowed=%s"
        ),
        user.user_id,
        requested_agent_id,
        selected_agent_id or None,
        selected_workspace,
        expected_agent_prefix,
        selected_owned_by_id,
        selected_owned_by_workspace,
        selected_allowed,
    )

    _, resolved_workspace = await _enforce_agent_ownership_or_404(
        ws,
        user,
        selected,
        requested_agent_id=requested_agent_id,
    )

    default_agent_id = str(list_payload.get("defaultId") or settings.openclaw_default_agent_id)
    summary = _normalize_agent_summary(
        {
            **selected,
            "workspace": resolved_workspace if resolved_workspace else selected.get("workspace"),
        },
        default_agent_id=default_agent_id,
        user_id=user.user_id,
    )

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
    user: AuthenticatedUser = Depends(get_current_user),
) -> AgentUpdateResponse:
    resolved_agent_id = _resolve_requested_agent_id_or_400(user, agent_id)

    ws = await _get_connected_ws()
    _ = await _get_owned_agent_or_404(ws, user, resolved_agent_id)

    params: Dict[str, Any] = {"agentId": resolved_agent_id}

    if body.name is not None:
        name = body.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="name cannot be empty")
        params["name"] = name

    if body.workspace is not None:
        workspace_input = body.workspace.strip()
        if not workspace_input:
            raise HTTPException(status_code=400, detail="workspace cannot be empty")
        try:
            workspace = normalize_workspace_for_user(user.user_id, workspace_input)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
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

    try:
        res = await ws.call("agents.update", params)
    except Exception as e:  # noqa: BLE001
        raise _map_ws_error("agents.update", e, not_found_agent_id=resolved_agent_id)

    return AgentUpdateResponse(
        updated=True,
        agent_id=resolved_agent_id,
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
    user: AuthenticatedUser = Depends(get_current_user),
) -> AgentDeleteResponse:
    resolved_agent_id = _resolve_requested_agent_id_or_400(user, agent_id)

    ws = await _get_connected_ws()
    _ = await _get_owned_agent_or_404(ws, user, resolved_agent_id)

    try:
        res = await ws.call("agents.delete", {"agentId": resolved_agent_id, "deleteFiles": delete_files})
    except Exception as e:  # noqa: BLE001
        raise _map_ws_error("agents.delete", e, not_found_agent_id=resolved_agent_id)

    removed_bindings: Optional[int] = None
    if isinstance(res, dict):
        rb = res.get("removedBindings")
        if isinstance(rb, int):
            removed_bindings = rb

    return AgentDeleteResponse(
        deleted=True,
        agent_id=resolved_agent_id,
        removed_bindings=removed_bindings,
        openclaw_result=(res if isinstance(res, dict) else {"payload": res}),
    )
