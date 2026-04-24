from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException

from app.core.knowledge_conversion import render_markdown_for_knowledge_upload
from app.core.knowledge_fs import (
    ALLOWED_KNOWLEDGE_EXTENSIONS,
    atomic_write_files,
    detect_mime_from_name,
    normalize_relative_path,
    plan_knowledge_mutation,
    plan_knowledge_write,
    reject_hardlinked_file,
    reject_symlink_chain,
    resolve_under_root,
    validate_allowed_extension,
)
from app.schemas.knowledge import KnowledgeFileMutationResponse


@dataclass(frozen=True)
class _PreparedKnowledgeWrite:
    response_rel: str
    response_target: Path
    writes: list[tuple[Path, bytes]]


MANAGED_MARKDOWN_WRITE_DETAIL = "Generated markdown siblings are managed by their paired original upload"


def _join_rel(folder_rel: str, filename: str) -> str:
    return f"{folder_rel}/{filename}" if folder_rel else filename


def _resolve_file(root: Path, file_rel: str) -> tuple[str, Path]:
    rel = normalize_relative_path(file_rel, allow_empty=False)
    target = resolve_under_root(root, rel)
    reject_symlink_chain(target.parent, stop_at=root)
    if target.exists():
        reject_hardlinked_file(target)
    return rel, target


def _folder_rel_for_file_rel(file_rel: str) -> str:
    folder_rel = normalize_relative_path(str(Path(file_rel).parent).replace("\\", "/"), allow_empty=True)
    return "" if folder_rel == "." else folder_rel


def _prepare_knowledge_write(root: Path, folder_rel: str, filename: str, data: bytes) -> tuple[_PreparedKnowledgeWrite, Path]:
    requested_rel = _join_rel(folder_rel, filename)
    _requested_rel, requested_target = _resolve_file(root, requested_rel)

    plan = plan_knowledge_write(requested_target.parent, requested_target.name)

    response_rel = _join_rel(folder_rel, plan.original_filename)
    response_rel, response_target = _resolve_file(root, response_rel)

    writes: list[tuple[Path, bytes]] = [(response_target, data)]
    if plan.stores_generated_markdown:
        markdown_rel = _join_rel(folder_rel, plan.markdown_filename or "")
        _markdown_rel, markdown_target = _resolve_file(root, markdown_rel)
        markdown_bytes = render_markdown_for_knowledge_upload(plan.original_filename, data)
        writes.append((markdown_target, markdown_bytes))

    return _PreparedKnowledgeWrite(response_rel=response_rel, response_target=response_target, writes=writes), requested_target


def _ensure_write_target_ok(target: Path, *, detail: str) -> None:
    if target.exists() and target.is_dir():
        raise HTTPException(status_code=409, detail=detail)
    if target.exists():
        reject_hardlinked_file(target)


def _store_knowledge_file(
    root: Path,
    folder_rel: str,
    filename: str,
    data: bytes,
    *,
    allow_overwrite: bool,
    allow_create: bool,
    exists_detail: str,
    missing_detail: str,
) -> tuple[str, Path]:
    requested_rel = _join_rel(folder_rel, filename)
    _requested_rel, requested_target = _resolve_file(root, requested_rel)

    mutation_plan = plan_knowledge_mutation(requested_target.parent, requested_target.name)
    if mutation_plan.is_managed_markdown:
        raise HTTPException(status_code=409, detail=MANAGED_MARKDOWN_WRITE_DETAIL)

    if requested_target.exists() and requested_target.is_dir():
        raise HTTPException(status_code=409, detail="Destination path is a folder")
    if requested_target.exists() and not allow_overwrite:
        raise HTTPException(status_code=409, detail=exists_detail)
    if not requested_target.exists() and not allow_create:
        raise HTTPException(status_code=404, detail=missing_detail)

    prepared, _ = _prepare_knowledge_write(root, folder_rel, filename, data)
    for target, _content in prepared.writes:
        detail = "Destination path is a folder" if target == prepared.response_target else "Generated markdown path is a folder"
        _ensure_write_target_ok(target, detail=detail)

    atomic_write_files(prepared.writes)
    return prepared.response_rel, prepared.response_target


def _file_write_result(aid: str, rel: str, target: Path, content: bytes, mime_type: str) -> KnowledgeFileMutationResponse:
    stat = target.stat()
    return KnowledgeFileMutationResponse(
        ok=True,
        agent_id=aid,
        path=rel,
        filename=target.name,
        size_bytes=stat.st_size,
        sha256=hashlib.sha256(content).hexdigest(),
        mime_type=mime_type,
        updated_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
    )


def execute_knowledge_upload(
    aid: str,
    root: Path,
    *,
    folder_rel: str,
    filename: str,
    data: bytes,
    overwrite: bool,
    mime_type: str | None,
) -> KnowledgeFileMutationResponse:
    normalized_folder_rel = normalize_relative_path(folder_rel, allow_empty=True)
    validate_allowed_extension(filename, ALLOWED_KNOWLEDGE_EXTENSIONS)

    rel, target = _store_knowledge_file(
        root,
        normalized_folder_rel,
        filename,
        data,
        allow_overwrite=overwrite,
        allow_create=True,
        exists_detail="File already exists; set overwrite=true",
        missing_detail="",
    )

    effective_mime_type = (mime_type or "").strip() or detect_mime_from_name(target.name)
    return _file_write_result(aid, rel, target, data, effective_mime_type)


def execute_knowledge_replace(
    aid: str,
    root: Path,
    *,
    file_rel: str,
    data: bytes,
    upsert: bool,
    mime_type: str | None,
) -> KnowledgeFileMutationResponse:
    rel, target = _resolve_file(root, file_rel)
    validate_allowed_extension(target.name, ALLOWED_KNOWLEDGE_EXTENSIONS)

    folder_rel = _folder_rel_for_file_rel(rel)
    rel, target = _store_knowledge_file(
        root,
        folder_rel,
        target.name,
        data,
        allow_overwrite=True,
        allow_create=upsert,
        exists_detail="",
        missing_detail="File not found; set upsert=true to create it",
    )

    effective_mime_type = (mime_type or "").strip() or detect_mime_from_name(target.name)
    return _file_write_result(aid, rel, target, data, effective_mime_type)
