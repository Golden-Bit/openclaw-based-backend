from __future__ import annotations

import asyncio
import hashlib
import logging
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.knowledge_fs import (
    KnowledgePathError,
    detect_mime_from_name,
    ensure_root_dir,
    knowledge_root_for_workspace,
    normalize_relative_path,
    plan_knowledge_mutation,
)
from app.core.knowledge_upload_executor import execute_knowledge_replace, execute_knowledge_upload
from app.db.models import KnowledgeUploadTask
from app.db.session import AsyncSessionLocal
from app.schemas.knowledge import (
    KnowledgeFileMutationResponse,
    KnowledgeFileTaskInfoResponse,
    KnowledgeUploadTaskAcceptedResponse,
    KnowledgeUploadTaskItem,
    KnowledgeUploadTaskListResponse,
    KnowledgeUploadTaskStatusResponse,
)

logger = logging.getLogger(__name__)

KNOWLEDGE_UPLOAD_TASK_TTL = timedelta(minutes=30)
KNOWLEDGE_UPLOAD_STAGE_DIRNAME = ".knowledge-upload-tasks"
_TERMINAL_TASK_STATUSES = {"succeeded", "failed", "expired"}
_LOCAL_TASKS: dict[str, asyncio.Task[None]] = {}


class KnowledgeUploadTaskNotFoundError(LookupError):
    pass


@dataclass(frozen=True)
class _KnowledgeFileTaskLookup:
    association_status: str
    canonical_path: str
    active_match_paths: tuple[str, ...]
    success_match_paths: tuple[str, ...]


def _utcnow() -> datetime:
    return datetime.utcnow()


def _task_key(task_id: uuid.UUID) -> str:
    return str(task_id)


def _task_stage_root(workspace: str) -> Path:
    return Path(workspace).expanduser().resolve() / "memory" / KNOWLEDGE_UPLOAD_STAGE_DIRNAME


def _task_stage_dir(workspace: str, task_id: uuid.UUID) -> Path:
    return _task_stage_root(workspace) / str(task_id)


def _payload_path(stage_dir: str | Path) -> Path:
    return Path(stage_dir) / "payload.bin"


def _cleanup_stage_dir(stage_dir: str | None) -> None:
    if not stage_dir:
        return
    try:
        shutil.rmtree(stage_dir)
    except FileNotFoundError:
        pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("knowledge_upload_task.cleanup_failed stage_dir=%s error=%s", stage_dir, exc)


def _is_task_active(task_id: uuid.UUID) -> bool:
    task = _LOCAL_TASKS.get(_task_key(task_id))
    return task is not None and not task.done()


def _task_requested_path(task: KnowledgeUploadTask) -> str:
    if task.requested_path:
        return task.requested_path
    if task.folder_path and task.filename:
        return f"{task.folder_path}/{task.filename}"
    return task.filename or ""


def _task_to_item(task: KnowledgeUploadTask) -> KnowledgeUploadTaskItem:
    return KnowledgeUploadTaskItem(
        task_id=task.id,
        agent_id=task.agent_id,
        status=task.status,
        source_kind=task.source_kind,
        requested_path=_task_requested_path(task),
        filename=task.filename,
        created_at=task.created_at,
        updated_at=task.updated_at,
        started_at=task.started_at,
        finished_at=task.finished_at,
        expires_at=task.expires_at,
    )


def _task_to_status(task: KnowledgeUploadTask) -> KnowledgeUploadTaskStatusResponse:
    result = None
    if task.result_payload:
        result = KnowledgeFileMutationResponse.model_validate(task.result_payload)
    return KnowledgeUploadTaskStatusResponse(
        **_task_to_item(task).model_dump(),
        result=result,
        error_detail=task.error_detail,
    )


def build_knowledge_upload_task_accepted_response(task: KnowledgeUploadTask) -> KnowledgeUploadTaskAcceptedResponse:
    return KnowledgeUploadTaskAcceptedResponse(
        accepted=True,
        task_id=task.id,
        agent_id=task.agent_id,
        status=task.status,
        created_at=task.created_at,
        expires_at=task.expires_at,
        status_url=f"/api/v1/agents/{task.agent_id}/knowledge/tasks/{task.id}",
    )


def _join_rel(folder_rel: str, filename: str) -> str:
    return f"{folder_rel}/{filename}" if folder_rel else filename


def _folder_rel_for_file_rel(file_rel: str) -> str:
    folder_rel = normalize_relative_path(str(Path(file_rel).parent).replace("\\", "/"), allow_empty=True)
    return "" if folder_rel == "." else folder_rel


def _task_result_path(task: KnowledgeUploadTask) -> str | None:
    payload = task.result_payload
    if not isinstance(payload, dict):
        return None
    result_path = payload.get("path")
    if not isinstance(result_path, str):
        return None
    normalized = result_path.strip()
    return normalized or None


def _build_knowledge_file_task_lookup(file_rel: str, target: Path) -> _KnowledgeFileTaskLookup:
    folder_rel = _folder_rel_for_file_rel(file_rel)
    try:
        plan = plan_knowledge_mutation(target.parent, target.name)
    except KnowledgePathError:
        return _KnowledgeFileTaskLookup(
            association_status="ambiguous",
            canonical_path=file_rel,
            active_match_paths=(file_rel,),
            success_match_paths=(),
        )

    if plan.is_managed_markdown and plan.managed_original_filename:
        canonical_path = _join_rel(folder_rel, plan.managed_original_filename)
        return _KnowledgeFileTaskLookup(
            association_status="managed_original",
            canonical_path=canonical_path,
            active_match_paths=(file_rel, canonical_path),
            success_match_paths=(canonical_path,),
        )

    return _KnowledgeFileTaskLookup(
        association_status="direct",
        canonical_path=file_rel,
        active_match_paths=(file_rel,),
        success_match_paths=(file_rel,),
    )


async def get_knowledge_file_task_info(
    db: AsyncSession,
    *,
    user_id: str,
    agent_id: str,
    file_rel: str,
    target: Path,
) -> KnowledgeFileTaskInfoResponse:
    lookup = _build_knowledge_file_task_lookup(file_rel, target)
    if lookup.association_status == "ambiguous":
        return KnowledgeFileTaskInfoResponse(
            association_status=lookup.association_status,
            canonical_path=lookup.canonical_path,
            active_task=None,
            latest_successful_task=None,
        )

    await expire_stale_knowledge_upload_tasks(db, user_id=user_id, agent_id=agent_id, include_running=True)
    stmt = (
        select(KnowledgeUploadTask)
        .where(
            KnowledgeUploadTask.user_id == user_id,
            KnowledgeUploadTask.agent_id == agent_id,
            KnowledgeUploadTask.status.in_(["pending", "running", "succeeded"]),
        )
        .order_by(KnowledgeUploadTask.updated_at.desc(), KnowledgeUploadTask.created_at.desc())
    )
    res = await db.execute(stmt)
    tasks = res.scalars().all()

    active_match_paths = set(lookup.active_match_paths)
    success_match_paths = set(lookup.success_match_paths)
    active_task = None
    latest_successful_task = None

    for task in tasks:
        if active_task is None and task.status in {"pending", "running"}:
            if _task_requested_path(task) in active_match_paths:
                active_task = _task_to_item(task)

        if latest_successful_task is None and task.status == "succeeded":
            if _task_result_path(task) in success_match_paths:
                latest_successful_task = _task_to_status(task)

        if active_task is not None and latest_successful_task is not None:
            break

    return KnowledgeFileTaskInfoResponse(
        association_status=lookup.association_status,
        canonical_path=lookup.canonical_path,
        active_task=active_task,
        latest_successful_task=latest_successful_task,
    )


async def create_knowledge_upload_task(
    db: AsyncSession,
    *,
    user_id: str,
    agent_id: str,
    workspace: str,
    source_kind: str,
    folder_path: str | None,
    requested_path: str | None,
    filename: str | None,
    mime_type: str | None,
    overwrite: bool,
    upsert: bool,
    data: bytes,
) -> KnowledgeUploadTask:
    task_id = uuid.uuid4()
    payload_path = stage_payload_for_knowledge_task(workspace, task_id, data)
    stage_dir = payload_path.parent

    now = _utcnow()
    task = KnowledgeUploadTask(
        id=task_id,
        user_id=user_id,
        agent_id=agent_id,
        workspace=workspace,
        source_kind=source_kind,
        folder_path=folder_path,
        requested_path=requested_path,
        filename=filename,
        mime_type=mime_type,
        overwrite=overwrite,
        upsert=upsert,
        stage_dir=stage_dir.as_posix(),
        staged_size_bytes=len(data),
        staged_sha256=hashlib.sha256(data).hexdigest(),
        status="pending",
        expires_at=now + KNOWLEDGE_UPLOAD_TASK_TTL,
    )

    try:
        db.add(task)
        await db.commit()
        await db.refresh(task)
    except Exception:
        _cleanup_stage_dir(stage_dir.as_posix())
        raise

    schedule_knowledge_upload_task(task.id)
    return task


async def expire_stale_knowledge_upload_tasks(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    user_id: str | None = None,
    agent_id: str | None = None,
    task_id: uuid.UUID | None = None,
    include_running: bool = True,
) -> list[KnowledgeUploadTask]:
    now = now or _utcnow()
    candidate_statuses = ["pending", "running"] if include_running else ["pending"]

    stmt = select(KnowledgeUploadTask).where(KnowledgeUploadTask.status.in_(candidate_statuses))
    if user_id is not None:
        stmt = stmt.where(KnowledgeUploadTask.user_id == user_id)
    if agent_id is not None:
        stmt = stmt.where(KnowledgeUploadTask.agent_id == agent_id)
    if task_id is not None:
        stmt = stmt.where(KnowledgeUploadTask.id == task_id)

    res = await db.execute(stmt)
    tasks = res.scalars().all()

    expired: list[KnowledgeUploadTask] = []
    cleanup_dirs: list[str] = []
    for task in tasks:
        if task.expires_at > now:
            continue
        if task.status == "running" and _is_task_active(task.id):
            continue
        task.status = "expired"
        task.finished_at = now
        task.updated_at = now
        task.error_detail = task.error_detail or "Task expired after 30 minutes"
        expired.append(task)
        cleanup_dirs.append(task.stage_dir)

    if expired:
        await db.commit()
        for stage_dir in cleanup_dirs:
            _cleanup_stage_dir(stage_dir)

    return expired


async def list_pending_knowledge_upload_tasks(
    db: AsyncSession,
    *,
    user_id: str,
    agent_id: str,
) -> KnowledgeUploadTaskListResponse:
    await expire_stale_knowledge_upload_tasks(db, user_id=user_id, agent_id=agent_id, include_running=False)
    stmt = (
        select(KnowledgeUploadTask)
        .where(
            KnowledgeUploadTask.user_id == user_id,
            KnowledgeUploadTask.agent_id == agent_id,
            KnowledgeUploadTask.status == "pending",
        )
        .order_by(KnowledgeUploadTask.created_at.desc())
    )
    res = await db.execute(stmt)
    items = [_task_to_item(task) for task in res.scalars().all()]
    return KnowledgeUploadTaskListResponse(agent_id=agent_id, items=items)


async def get_owned_knowledge_upload_task_or_404(
    db: AsyncSession,
    *,
    user_id: str,
    agent_id: str,
    task_id: uuid.UUID,
) -> KnowledgeUploadTask:
    stmt = select(KnowledgeUploadTask).where(
        KnowledgeUploadTask.id == task_id,
        KnowledgeUploadTask.user_id == user_id,
        KnowledgeUploadTask.agent_id == agent_id,
    )
    res = await db.execute(stmt)
    task = res.scalar_one_or_none()
    if task is None:
        raise KnowledgeUploadTaskNotFoundError(str(task_id))
    return task


async def get_knowledge_upload_task_status(
    db: AsyncSession,
    *,
    user_id: str,
    agent_id: str,
    task_id: uuid.UUID,
) -> KnowledgeUploadTaskStatusResponse:
    await expire_stale_knowledge_upload_tasks(
        db,
        user_id=user_id,
        agent_id=agent_id,
        task_id=task_id,
        include_running=True,
    )
    task = await get_owned_knowledge_upload_task_or_404(db, user_id=user_id, agent_id=agent_id, task_id=task_id)
    return _task_to_status(task)


async def recover_knowledge_upload_tasks() -> None:
    async with AsyncSessionLocal() as db:
        now = _utcnow()
        await expire_stale_knowledge_upload_tasks(db, now=now, include_running=True)

        stmt = select(KnowledgeUploadTask).where(KnowledgeUploadTask.status.in_(["pending", "running"]))
        res = await db.execute(stmt)
        tasks = res.scalars().all()

        to_schedule: list[uuid.UUID] = []
        changed = False
        for task in tasks:
            if task.expires_at <= now:
                continue
            if task.status == "running":
                task.status = "pending"
                task.started_at = None
                task.updated_at = now
                changed = True
            to_schedule.append(task.id)

        if changed:
            await db.commit()

    for task_id in to_schedule:
        schedule_knowledge_upload_task(task_id)


async def shutdown_knowledge_upload_tasks() -> None:
    tasks = list(_LOCAL_TASKS.values())
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _finalize_task_success(task_id: uuid.UUID, result: KnowledgeFileMutationResponse) -> None:
    async with AsyncSessionLocal() as db:
        task = await db.get(KnowledgeUploadTask, task_id)
        if task is None or task.status in _TERMINAL_TASK_STATUSES:
            return
        task.status = "succeeded"
        task.result_payload = result.model_dump(mode="json")
        task.error_detail = None
        task.finished_at = _utcnow()
        task.updated_at = task.finished_at
        await db.commit()
        stage_dir = task.stage_dir
    _cleanup_stage_dir(stage_dir)


async def _finalize_task_failure(task_id: uuid.UUID, detail: str, *, status: str = "failed") -> None:
    async with AsyncSessionLocal() as db:
        task = await db.get(KnowledgeUploadTask, task_id)
        if task is None or task.status in _TERMINAL_TASK_STATUSES:
            return
        task.status = status
        task.error_detail = detail
        task.finished_at = _utcnow()
        task.updated_at = task.finished_at
        await db.commit()
        stage_dir = task.stage_dir
    _cleanup_stage_dir(stage_dir)


async def _claim_task_for_run(task_id: uuid.UUID) -> KnowledgeUploadTask | None:
    async with AsyncSessionLocal() as db:
        task = await db.get(KnowledgeUploadTask, task_id)
        if task is None:
            return None
        if task.status != "pending":
            return None
        now = _utcnow()
        if task.expires_at <= now:
            task.status = "expired"
            task.finished_at = now
            task.updated_at = now
            task.error_detail = "Task expired after 30 minutes"
            await db.commit()
            stage_dir = task.stage_dir
        else:
            task.status = "running"
            task.started_at = now
            task.updated_at = now
            await db.commit()
            await db.refresh(task)
            return task
    _cleanup_stage_dir(stage_dir)
    return None


def _execute_task_sync(task: KnowledgeUploadTask) -> KnowledgeFileMutationResponse:
    payload_path = _payload_path(task.stage_dir)
    data = payload_path.read_bytes()
    root = knowledge_root_for_workspace(task.workspace)
    ensure_root_dir(root)

    if task.source_kind in {"multipart", "base64"}:
        effective_mime = (task.mime_type or "").strip() or detect_mime_from_name(task.filename or "file")
        return execute_knowledge_upload(
            task.agent_id,
            root,
            folder_rel=task.folder_path or "",
            filename=task.filename or "",
            data=data,
            overwrite=task.overwrite,
            mime_type=effective_mime,
        )

    effective_path = task.requested_path or task.filename or ""
    effective_mime = (task.mime_type or "").strip() or detect_mime_from_name(Path(effective_path).name)
    return execute_knowledge_replace(
        task.agent_id,
        root,
        file_rel=effective_path,
        data=data,
        upsert=task.upsert,
        mime_type=effective_mime,
    )


async def _run_knowledge_upload_task(task_id: uuid.UUID) -> None:
    task = await _claim_task_for_run(task_id)
    if task is None:
        return

    try:
        result = await asyncio.to_thread(_execute_task_sync, task)
    except Exception as exc:  # noqa: BLE001
        if isinstance(exc, HTTPException):
            detail = str(exc.detail)
        else:
            detail = str(exc)
        await _finalize_task_failure(task_id, detail)
        return

    await _finalize_task_success(task_id, result)


async def _runner_wrapper(task_id: uuid.UUID) -> None:
    try:
        await _run_knowledge_upload_task(task_id)
    finally:
        _LOCAL_TASKS.pop(_task_key(task_id), None)


def schedule_knowledge_upload_task(task_id: uuid.UUID) -> None:
    key = _task_key(task_id)
    existing = _LOCAL_TASKS.get(key)
    if existing is not None and not existing.done():
        return
    _LOCAL_TASKS[key] = asyncio.create_task(_runner_wrapper(task_id))


def stage_payload_for_knowledge_task(workspace: str, task_id: uuid.UUID, data: bytes) -> Path:
    stage_dir = _task_stage_dir(workspace, task_id)
    ensure_root_dir(stage_dir)
    payload_path = _payload_path(stage_dir)
    payload_path.write_bytes(data)
    return payload_path
