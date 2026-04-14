from __future__ import annotations

import mimetypes

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from app.core.config import settings
from app.core.shared_files import SharedFilePathError, normalize_shared_url_prefix, resolve_shared_file_path


def _shared_prefix() -> str:
    return normalize_shared_url_prefix(settings.shared_files_url_prefix)


router = APIRouter(prefix=_shared_prefix())


def _should_download(*, download: bool | None, inline: bool) -> bool:
    if inline:
        return False
    if download is None:
        return True
    return download


@router.get("/{requested_path:path}", summary="Serve file from shared hosting root")
async def get_shared_file(
    requested_path: str,
    download: bool | None = Query(
        default=None,
        description="Se true forza attachment, se false forza preview inline. Default: download diretto.",
    ),
    inline: bool = Query(default=False, description="Se true forza preview inline nel browser."),
) -> FileResponse:
    try:
        target = resolve_shared_file_path(requested_path)
    except SharedFilePathError:
        raise HTTPException(status_code=404, detail="File not found")

    if not target.exists() or not target.is_file() or target.is_symlink():
        raise HTTPException(status_code=404, detail="File not found")

    media_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"

    if _should_download(download=download, inline=inline):
        return FileResponse(path=target, filename=target.name, media_type=media_type)
    return FileResponse(path=target, media_type=media_type)
