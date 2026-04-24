from __future__ import annotations

import base64
import errno
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints import agents as agents_endpoint
from app.core.agent_ownership import is_agent_id_owned_by_user, resolve_requested_agent_id_for_user
from app.core.config import settings
from app.core.knowledge_conversion import (
    KnowledgeConversionDependencyError,
    KnowledgeConversionError,
)
from app.core.knowledge_fs import (
    ALLOWED_KNOWLEDGE_EXTENSIONS,
    KnowledgePathError,
    atomic_delete_files,
    detect_mime_from_name,
    ensure_root_dir,
    knowledge_root_for_workspace,
    normalize_relative_path,
    plan_knowledge_mutation,
    reject_hardlinked_file,
    reject_symlink_chain,
    resolve_under_root,
    validate_allowed_extension,
)
from app.core.knowledge_upload_executor import execute_knowledge_replace, execute_knowledge_upload
from app.core.knowledge_upload_tasks import (
    KnowledgeUploadTaskNotFoundError,
    build_knowledge_upload_task_accepted_response,
    create_knowledge_upload_task,
    get_knowledge_file_task_info,
    get_knowledge_upload_task_status,
    list_pending_knowledge_upload_tasks,
)
from app.core.security import AuthenticatedUser, get_current_user
from app.db.session import get_db
from app.schemas.knowledge import (
    KnowledgeFileBase64UploadRequest,
    KnowledgeFileContentResponse,
    KnowledgeFileDeleteResponse,
    KnowledgeFileInfoResponse,
    KnowledgeFileMutationResponse,
    KnowledgeFilePutRequest,
    KnowledgeFolderCreateRequest,
    KnowledgeFolderDeleteResponse,
    KnowledgeFolderMoveRequest,
    KnowledgeFolderMutationResponse,
    KnowledgeReindexResponse,
    KnowledgeTreeItem,
    KnowledgeTreeResponse,
    KnowledgeUploadTaskAcceptedResponse,
    KnowledgeUploadTaskListResponse,
    KnowledgeUploadTaskStatusResponse,
)

router = APIRouter(prefix="/agents/{agent_id}/knowledge")

def _sanitize_filename(name: str) -> str:
    cleaned = os.path.basename((name or "").strip().replace("\\", "/"))
    if not cleaned:
        raise HTTPException(status_code=400, detail="filename is required")
    if cleaned in {".", ".."}:
        raise HTTPException(status_code=400, detail="invalid filename")
    if ":" in cleaned:
        raise HTTPException(status_code=400, detail="invalid filename")
    return cleaned


def _ensure_size_ok(size: int) -> None:
    if size > settings.upload_max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large: {size} bytes (max {settings.upload_max_bytes})",
        )


def _map_path_error(err: Exception) -> HTTPException:
    if isinstance(err, FileNotFoundError):
        return HTTPException(status_code=404, detail="Path not found")
    if isinstance(err, KnowledgePathError):
        return HTTPException(status_code=400, detail=str(err))
    if isinstance(err, PermissionError):
        return HTTPException(status_code=403, detail="Permission denied")
    return HTTPException(status_code=500, detail=f"Filesystem error: {err}")


async def _resolve_agent_workspace(ws, agent_id: str) -> str:
    # Primo tentativo: agents.files.list (normalmente include workspace)
    try:
        files_payload = await ws.call("agents.files.list", {"agentId": agent_id})
        if isinstance(files_payload, dict):
            workspace = files_payload.get("workspace")
            if isinstance(workspace, str) and workspace.strip():
                return workspace.strip()
    except Exception:
        # fallback su agents.list
        pass

    try:
        payload = await ws.call("agents.list", {})
    except Exception as e:  # noqa: BLE001
        raise agents_endpoint._map_ws_error("agents.list", e, not_found_agent_id=agent_id)

    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail=f"Unexpected OpenClaw payload for agents.list: {payload!r}")

    raw_agents = payload.get("agents")
    if not isinstance(raw_agents, list):
        raw_agents = []

    selected = agents_endpoint._find_agent(raw_agents, agent_id)
    if selected is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    workspace_raw = selected.get("workspace")
    if not isinstance(workspace_raw, str) or not workspace_raw.strip():
        raise HTTPException(
            status_code=409,
            detail=f"Agent '{agent_id}' has no workspace configured. Update agent workspace first.",
        )
    return workspace_raw.strip()


async def _agent_context(agent_id: str, user: AuthenticatedUser):
    try:
        aid = resolve_requested_agent_id_for_user(user.user_id, agent_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not is_agent_id_owned_by_user(user.user_id, aid):
        raise HTTPException(status_code=404, detail=f"Agent '{aid}' not found")

    ws = await agents_endpoint._get_connected_ws()
    workspace = await _resolve_agent_workspace(ws, aid)
    workspace_path = Path(workspace).expanduser()
    if not workspace_path.is_absolute():
        raise HTTPException(status_code=409, detail=f"Agent '{aid}' workspace must be an absolute path")
    root = knowledge_root_for_workspace(workspace)
    ensure_root_dir(root)
    return aid, ws, workspace, root


def _owned_agent_id(agent_id: str, user: AuthenticatedUser) -> str:
    try:
        aid = resolve_requested_agent_id_for_user(user.user_id, agent_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not is_agent_id_owned_by_user(user.user_id, aid):
        raise HTTPException(status_code=404, detail=f"Agent '{aid}' not found")
    return aid


async def _enqueue_knowledge_upload_task_response(
    db: AsyncSession,
    *,
    user_id: str,
    aid: str,
    workspace: str,
    source_kind: str,
    folder_path: str | None,
    requested_path: str | None,
    filename: str | None,
    mime_type: str | None,
    overwrite: bool,
    upsert: bool,
    data: bytes,
) -> KnowledgeUploadTaskAcceptedResponse:
    task = await create_knowledge_upload_task(
        db,
        user_id=user_id,
        agent_id=aid,
        workspace=workspace,
        source_kind=source_kind,
        folder_path=folder_path,
        requested_path=requested_path,
        filename=filename,
        mime_type=mime_type,
        overwrite=overwrite,
        upsert=upsert,
        data=data,
    )
    return build_knowledge_upload_task_accepted_response(task)


def _resolve_folder(root: Path, path_value: str, *, allow_empty: bool) -> tuple[str, Path]:
    rel = normalize_relative_path(path_value, allow_empty=allow_empty)
    target = resolve_under_root(root, rel)
    reject_symlink_chain(target, stop_at=root)
    return rel, target


def _resolve_file(root: Path, file_rel: str) -> tuple[str, Path]:
    rel = normalize_relative_path(file_rel, allow_empty=False)
    target = resolve_under_root(root, rel)
    reject_symlink_chain(target.parent, stop_at=root)
    if target.exists():
        reject_hardlinked_file(target)
    return rel, target


def _iter_tree(root: Path, base: Path) -> list[KnowledgeTreeItem]:
    items: list[KnowledgeTreeItem] = []
    for entry in sorted(base.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        if entry.is_symlink():
            continue
        rel = entry.relative_to(root).as_posix()
        stat = entry.stat()
        if entry.is_dir():
            items.append(
                KnowledgeTreeItem(
                    path=rel,
                    name=entry.name,
                    kind="folder",
                    size_bytes=None,
                    updated_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                )
            )
        elif entry.is_file():
            if getattr(stat, "st_nlink", 1) > 1:
                continue
            items.append(
                KnowledgeTreeItem(
                    path=rel,
                    name=entry.name,
                    kind="file",
                    size_bytes=stat.st_size,
                    updated_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                )
            )
    return items


@router.get("/tree", response_model=KnowledgeTreeResponse, summary="Lista tree knowledge agente")
async def knowledge_tree(
    agent_id: str,
    path: str = Query(default="", description="Path relativa dentro memory/knowledge"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> KnowledgeTreeResponse:
    aid, _ws, workspace, root = await _agent_context(agent_id, user)
    try:
        rel, base = _resolve_folder(root, path, allow_empty=True)
        if not base.exists():
            raise FileNotFoundError(str(base))
        if not base.is_dir():
            raise HTTPException(status_code=409, detail="Requested path is not a folder")
        items = _iter_tree(root, base)
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise _map_path_error(e)

    return KnowledgeTreeResponse(
        agent_id=aid,
        workspace=workspace,
        root=root.as_posix(),
        path=rel,
        items=items,
    )


@router.post("/folders", response_model=KnowledgeFolderMutationResponse, summary="Crea cartella knowledge")
async def create_folder(
    agent_id: str,
    body: KnowledgeFolderCreateRequest,
    user: AuthenticatedUser = Depends(get_current_user),
) -> KnowledgeFolderMutationResponse:
    aid, _ws, _workspace, root = await _agent_context(agent_id, user)
    try:
        rel, target = _resolve_folder(root, body.path, allow_empty=False)
        if target.exists() and not target.is_dir():
            raise HTTPException(status_code=409, detail="A file already exists at requested folder path")
        target.mkdir(parents=True, exist_ok=True)
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise _map_path_error(e)

    return KnowledgeFolderMutationResponse(ok=True, agent_id=aid, path=rel)


@router.patch("/folders", response_model=KnowledgeFolderMutationResponse, summary="Rinomina/sposta cartella knowledge")
async def move_folder(
    agent_id: str,
    body: KnowledgeFolderMoveRequest,
    user: AuthenticatedUser = Depends(get_current_user),
) -> KnowledgeFolderMutationResponse:
    aid, _ws, _workspace, root = await _agent_context(agent_id, user)
    try:
        from_rel, src = _resolve_folder(root, body.from_path, allow_empty=False)
        to_rel, dst = _resolve_folder(root, body.to_path, allow_empty=False)

        if from_rel == to_rel:
            raise HTTPException(status_code=400, detail="from_path and to_path are identical")
        if not src.exists() or not src.is_dir():
            raise FileNotFoundError(str(src))
        if dst.exists():
            raise HTTPException(status_code=409, detail="Destination path already exists")

        dst.parent.mkdir(parents=True, exist_ok=True)
        src.rename(dst)
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise _map_path_error(e)

    return KnowledgeFolderMutationResponse(ok=True, agent_id=aid, path=to_rel)


@router.delete("/folders", response_model=KnowledgeFolderDeleteResponse, summary="Elimina cartella knowledge")
async def delete_folder(
    agent_id: str,
    path: str = Query(..., description="Path relativa cartella"),
    recursive: bool = Query(default=True),
    user: AuthenticatedUser = Depends(get_current_user),
) -> KnowledgeFolderDeleteResponse:
    aid, _ws, _workspace, root = await _agent_context(agent_id, user)
    try:
        rel, target = _resolve_folder(root, path, allow_empty=False)
        if not target.exists() or not target.is_dir():
            raise FileNotFoundError(str(target))

        if recursive:
            shutil.rmtree(target)
        else:
            target.rmdir()
    except HTTPException:
        raise
    except OSError as e:
        if getattr(e, "errno", None) == errno.ENOTEMPTY:
            raise HTTPException(status_code=409, detail="Folder is not empty")
        raise _map_path_error(e)
    except Exception as e:  # noqa: BLE001
        raise _map_path_error(e)

    return KnowledgeFolderDeleteResponse(deleted=True, agent_id=aid, path=rel)


def _join_rel(folder_rel: str, filename: str) -> str:
    return f"{folder_rel}/{filename}" if folder_rel else filename


def _folder_rel_for_file_rel(file_rel: str) -> str:
    folder_rel = normalize_relative_path(str(Path(file_rel).parent).replace("\\", "/"), allow_empty=True)
    return "" if folder_rel == "." else folder_rel


def _delete_targets_for_file(root: Path, file_rel: str, target: Path) -> list[tuple[str, Path]]:
    plan = plan_knowledge_mutation(target.parent, target.name)
    folder_rel = _folder_rel_for_file_rel(file_rel)
    delete_targets: list[tuple[str, Path]] = []
    seen: set[str] = set()

    for filename in plan.delete_filenames:
        candidate_rel = _join_rel(folder_rel, filename)
        resolved_rel, resolved_target = _resolve_file(root, candidate_rel)
        if resolved_rel in seen:
            continue
        seen.add(resolved_rel)
        delete_targets.append((resolved_rel, resolved_target))

    return delete_targets


@router.post("/files/upload", response_model=KnowledgeFileMutationResponse, summary="Upload multipart file in knowledge")
async def upload_file(
    agent_id: str,
    file: UploadFile = File(...),
    path: str = Form(default="", description="Path relativa cartella destinazione"),
    filename: str | None = Form(default=None, description="Filename opzionale override"),
    overwrite: bool = Form(default=False),
    user: AuthenticatedUser = Depends(get_current_user),
) -> KnowledgeFileMutationResponse:
    aid, _ws, _workspace, root = await _agent_context(agent_id, user)
    try:
        folder_rel = normalize_relative_path(path, allow_empty=True)
        final_name = _sanitize_filename(filename or file.filename or "")
        validate_allowed_extension(final_name, ALLOWED_KNOWLEDGE_EXTENSIONS)

        data = await file.read()
        _ensure_size_ok(len(data))

        mime_type = (file.content_type or "").strip() or detect_mime_from_name(final_name)
        return execute_knowledge_upload(
            aid,
            root,
            folder_rel=folder_rel,
            filename=final_name,
            data=data,
            overwrite=overwrite,
            mime_type=mime_type,
        )
    except HTTPException:
        raise
    except KnowledgeConversionDependencyError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except KnowledgeConversionError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise _map_path_error(e)


@router.post("/files/base64", response_model=KnowledgeFileMutationResponse, summary="Upload base64 file in knowledge")
async def upload_file_base64(
    agent_id: str,
    body: KnowledgeFileBase64UploadRequest,
    user: AuthenticatedUser = Depends(get_current_user),
) -> KnowledgeFileMutationResponse:
    aid, _ws, _workspace, root = await _agent_context(agent_id, user)
    try:
        folder_rel = normalize_relative_path(body.path, allow_empty=True)
        final_name = _sanitize_filename(body.filename)
        validate_allowed_extension(final_name, ALLOWED_KNOWLEDGE_EXTENSIONS)

        data = base64.b64decode(body.content_base64, validate=True)
        _ensure_size_ok(len(data))

        mime_type = (body.mime_type or "").strip() or detect_mime_from_name(final_name)
        return execute_knowledge_upload(
            aid,
            root,
            folder_rel=folder_rel,
            filename=final_name,
            data=data,
            overwrite=body.overwrite,
            mime_type=mime_type,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 payload: {e}")
    except HTTPException:
        raise
    except KnowledgeConversionDependencyError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except KnowledgeConversionError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise _map_path_error(e)


@router.put("/files", response_model=KnowledgeFileMutationResponse, summary="Replace file content in knowledge")
async def replace_file(
    agent_id: str,
    body: KnowledgeFilePutRequest,
    user: AuthenticatedUser = Depends(get_current_user),
) -> KnowledgeFileMutationResponse:
    aid, _ws, _workspace, root = await _agent_context(agent_id, user)
    try:
        rel, target = _resolve_file(root, body.path)
        validate_allowed_extension(target.name, ALLOWED_KNOWLEDGE_EXTENSIONS)

        data = base64.b64decode(body.content_base64, validate=True)
        _ensure_size_ok(len(data))

        mime_type = (body.mime_type or "").strip() or detect_mime_from_name(target.name)
        return execute_knowledge_replace(
            aid,
            root,
            file_rel=rel,
            data=data,
            upsert=body.upsert,
            mime_type=mime_type,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 payload: {e}")
    except HTTPException:
        raise
    except KnowledgeConversionDependencyError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except KnowledgeConversionError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise _map_path_error(e)


@router.post(
    "/files/upload/background",
    response_model=KnowledgeUploadTaskAcceptedResponse,
    status_code=202,
    summary="Enqueue multipart knowledge upload",
)
async def upload_file_background(
    agent_id: str,
    file: UploadFile = File(...),
    path: str = Form(default="", description="Path relativa cartella destinazione"),
    filename: str | None = Form(default=None, description="Filename opzionale override"),
    overwrite: bool = Form(default=False),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> KnowledgeUploadTaskAcceptedResponse:
    aid, _ws, workspace, _root = await _agent_context(agent_id, user)
    try:
        folder_rel = normalize_relative_path(path, allow_empty=True)
        final_name = _sanitize_filename(filename or file.filename or "")
        validate_allowed_extension(final_name, ALLOWED_KNOWLEDGE_EXTENSIONS)

        data = await file.read()
        _ensure_size_ok(len(data))

        mime_type = (file.content_type or "").strip() or detect_mime_from_name(final_name)
        return await _enqueue_knowledge_upload_task_response(
            db,
            user_id=user.user_id,
            aid=aid,
            workspace=workspace,
            source_kind="multipart",
            folder_path=folder_rel,
            requested_path=None,
            filename=final_name,
            mime_type=mime_type,
            overwrite=overwrite,
            upsert=False,
            data=data,
        )
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise _map_path_error(e)


@router.post(
    "/files/base64/background",
    response_model=KnowledgeUploadTaskAcceptedResponse,
    status_code=202,
    summary="Enqueue base64 knowledge upload",
)
async def upload_file_base64_background(
    agent_id: str,
    body: KnowledgeFileBase64UploadRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> KnowledgeUploadTaskAcceptedResponse:
    aid, _ws, workspace, _root = await _agent_context(agent_id, user)
    try:
        folder_rel = normalize_relative_path(body.path, allow_empty=True)
        final_name = _sanitize_filename(body.filename)
        validate_allowed_extension(final_name, ALLOWED_KNOWLEDGE_EXTENSIONS)

        data = base64.b64decode(body.content_base64, validate=True)
        _ensure_size_ok(len(data))

        mime_type = (body.mime_type or "").strip() or detect_mime_from_name(final_name)
        return await _enqueue_knowledge_upload_task_response(
            db,
            user_id=user.user_id,
            aid=aid,
            workspace=workspace,
            source_kind="base64",
            folder_path=folder_rel,
            requested_path=None,
            filename=final_name,
            mime_type=mime_type,
            overwrite=body.overwrite,
            upsert=False,
            data=data,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 payload: {e}")
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise _map_path_error(e)


@router.put(
    "/files/background",
    response_model=KnowledgeUploadTaskAcceptedResponse,
    status_code=202,
    summary="Enqueue replace file content in knowledge",
)
async def replace_file_background(
    agent_id: str,
    body: KnowledgeFilePutRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> KnowledgeUploadTaskAcceptedResponse:
    aid, _ws, workspace, root = await _agent_context(agent_id, user)
    try:
        rel, target = _resolve_file(root, body.path)
        validate_allowed_extension(target.name, ALLOWED_KNOWLEDGE_EXTENSIONS)

        data = base64.b64decode(body.content_base64, validate=True)
        _ensure_size_ok(len(data))

        mime_type = (body.mime_type or "").strip() or detect_mime_from_name(target.name)
        return await _enqueue_knowledge_upload_task_response(
            db,
            user_id=user.user_id,
            aid=aid,
            workspace=workspace,
            source_kind="replace",
            folder_path=None,
            requested_path=rel,
            filename=target.name,
            mime_type=mime_type,
            overwrite=True,
            upsert=body.upsert,
            data=data,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 payload: {e}")
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise _map_path_error(e)


@router.get(
    "/tasks/pending",
    response_model=KnowledgeUploadTaskListResponse,
    summary="List pending background knowledge upload tasks",
)
async def list_pending_background_tasks(
    agent_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> KnowledgeUploadTaskListResponse:
    aid = _owned_agent_id(agent_id, user)
    return await list_pending_knowledge_upload_tasks(db, user_id=user.user_id, agent_id=aid)


@router.get(
    "/tasks/{task_id}",
    response_model=KnowledgeUploadTaskStatusResponse,
    summary="Get background knowledge upload task status",
)
async def get_background_task_status(
    agent_id: str,
    task_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> KnowledgeUploadTaskStatusResponse:
    aid = _owned_agent_id(agent_id, user)
    try:
        return await get_knowledge_upload_task_status(db, user_id=user.user_id, agent_id=aid, task_id=task_id)
    except KnowledgeUploadTaskNotFoundError:
        raise HTTPException(status_code=404, detail="Knowledge upload task not found") from None


@router.delete("/files", response_model=KnowledgeFileDeleteResponse, summary="Delete file in knowledge")
async def delete_file(
    agent_id: str,
    path: str = Query(..., description="Path relativa file"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> KnowledgeFileDeleteResponse:
    aid, _ws, _workspace, root = await _agent_context(agent_id, user)
    try:
        rel, target = _resolve_file(root, path)
        delete_targets = _delete_targets_for_file(root, rel, target)

        requested_exists = False
        existing_targets: list[Path] = []
        for delete_rel, delete_target in delete_targets:
            exists_as_file = delete_target.exists() and delete_target.is_file()
            if delete_rel == rel:
                requested_exists = exists_as_file
            if exists_as_file:
                reject_hardlinked_file(delete_target)
                existing_targets.append(delete_target)

        if not requested_exists:
            raise FileNotFoundError(str(target))

        atomic_delete_files(existing_targets)
    except Exception as e:  # noqa: BLE001
        raise _map_path_error(e)

    return KnowledgeFileDeleteResponse(deleted=True, agent_id=aid, path=rel)


@router.get("/files/info", response_model=KnowledgeFileInfoResponse, summary="Read file metadata from knowledge")
async def get_file_info(
    agent_id: str,
    path: str = Query(..., description="Path relativa file"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> KnowledgeFileInfoResponse:
    aid, _ws, _workspace, root = await _agent_context(agent_id, user)
    try:
        rel, target = _resolve_file(root, path)
        if not target.exists() or not target.is_file():
            raise FileNotFoundError(str(target))
        reject_hardlinked_file(target)

        stat = target.stat()
        task_info = await get_knowledge_file_task_info(
            db,
            user_id=user.user_id,
            agent_id=aid,
            file_rel=rel,
            target=target,
        )
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise _map_path_error(e)

    mime_type = detect_mime_from_name(target.name)
    return KnowledgeFileInfoResponse(
        agent_id=aid,
        path=rel,
        filename=target.name,
        size_bytes=stat.st_size,
        mime_type=mime_type,
        updated_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
        task_info=task_info,
    )


@router.get("/files/content", response_model=KnowledgeFileContentResponse, summary="Read file content from knowledge")
async def read_file_content(
    agent_id: str,
    path: str = Query(..., description="Path relativa file"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> KnowledgeFileContentResponse:
    aid, _ws, _workspace, root = await _agent_context(agent_id, user)
    try:
        rel, target = _resolve_file(root, path)
        if not target.exists() or not target.is_file():
            raise FileNotFoundError(str(target))
        reject_hardlinked_file(target)

        data = target.read_bytes()
        stat = target.stat()
    except Exception as e:  # noqa: BLE001
        raise _map_path_error(e)

    mime_type = detect_mime_from_name(target.name)
    try:
        text = data.decode("utf-8")
        content_text = text
        content_base64 = None
    except UnicodeDecodeError:
        content_text = None
        content_base64 = base64.b64encode(data).decode("ascii")

    return KnowledgeFileContentResponse(
        agent_id=aid,
        path=rel,
        filename=target.name,
        size_bytes=stat.st_size,
        mime_type=mime_type,
        updated_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
        content_text=content_text,
        content_base64=content_base64,
    )


@router.get("/files/download", summary="Download file from knowledge")
async def download_file(
    agent_id: str,
    path: str = Query(..., description="Path relativa file"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> FileResponse:
    _aid, _ws, _workspace, root = await _agent_context(agent_id, user)
    try:
        _rel, target = _resolve_file(root, path)
        if not target.exists() or not target.is_file():
            raise FileNotFoundError(str(target))
        reject_hardlinked_file(target)
    except Exception as e:  # noqa: BLE001
        raise _map_path_error(e)

    media_type = detect_mime_from_name(target.name)
    return FileResponse(path=target, filename=target.name, media_type=media_type)


@router.post(
    "/reindex",
    response_model=KnowledgeReindexResponse,
    status_code=202,
    summary="Best-effort memory reindex trigger",
)
async def reindex_knowledge(
    agent_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
) -> KnowledgeReindexResponse:
    aid, ws, _workspace, _root = await _agent_context(agent_id, user)

    warnings: list[str] = []
    details: dict[str, Any] | None = None

    # Best-effort ping: non esiste un trigger reindex univoco nel protocollo gateway
    try:
        status_payload = await ws.call("doctor.memory.status", {})
        details = status_payload if isinstance(status_payload, dict) else {"payload": status_payload}
    except Exception as e:  # noqa: BLE001
        warnings.append(f"doctor.memory.status unavailable: {e}")

    return KnowledgeReindexResponse(
        accepted=True,
        agent_id=aid,
        mode="eventual",
        details=details,
        warnings=warnings,
    )
