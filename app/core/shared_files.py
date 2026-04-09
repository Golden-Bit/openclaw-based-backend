from __future__ import annotations

from pathlib import Path, PurePosixPath
from urllib.parse import unquote

from app.core.config import settings


class SharedFilePathError(ValueError):
    """Invalid shared-file URL path."""


def shared_files_root() -> Path:
    return Path(settings.shared_files_root).expanduser().resolve()


def ensure_shared_files_root() -> Path:
    root = shared_files_root()
    root.mkdir(parents=True, exist_ok=True)
    return root


def normalize_shared_url_prefix(raw_prefix: str | None) -> str:
    raw = (raw_prefix or "").strip() or "/shared/files"
    if not raw.startswith("/"):
        raw = "/" + raw
    raw = raw.rstrip("/")
    return raw or "/shared/files"


def normalize_shared_relative_path(raw_path: str) -> str:
    decoded = unquote((raw_path or "").strip()).replace("\\", "/")
    if not decoded:
        raise SharedFilePathError("path is required")
    if decoded.startswith("/") or decoded.startswith("~"):
        raise SharedFilePathError("absolute paths are not allowed")

    p = PurePosixPath(decoded)
    clean_parts: list[str] = []
    for part in p.parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise SharedFilePathError("path traversal is not allowed")
        if ":" in part:
            raise SharedFilePathError("invalid path segment")
        clean_parts.append(part)

    normalized = "/".join(clean_parts)
    if not normalized:
        raise SharedFilePathError("path is required")
    return normalized


def resolve_shared_file_path(raw_path: str) -> Path:
    root = shared_files_root()
    rel = normalize_shared_relative_path(raw_path)
    target = (root / rel).resolve()

    try:
        target.relative_to(root)
    except ValueError as e:
        raise SharedFilePathError("path escapes shared root") from e

    return target
