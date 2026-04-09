from __future__ import annotations

import mimetypes

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from app.core.config import settings
from app.core.shared_files import SharedFilePathError, resolve_shared_file_path


def _shared_prefix() -> str:
    raw = (settings.shared_files_url_prefix or "").strip() or "/shared/files"
    if not raw.startswith("/"):
        raw = "/" + raw
    raw = raw.rstrip("/")
    return raw or "/shared/files"


router = APIRouter(prefix=_shared_prefix())


@router.get("/{requested_path:path}", summary="Serve file from shared hosting root")
async def get_shared_file(
    requested_path: str,
    download: bool = Query(default=False, description="Se true forza download attachment"),
) -> FileResponse:
    try:
        target = resolve_shared_file_path(requested_path)
    except SharedFilePathError:
        raise HTTPException(status_code=404, detail="File not found")

    if not target.exists() or not target.is_file() or target.is_symlink():
        raise HTTPException(status_code=404, detail="File not found")

    media_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"

    if download:
        return FileResponse(path=target, filename=target.name, media_type=media_type)
    return FileResponse(path=target, media_type=media_type)
