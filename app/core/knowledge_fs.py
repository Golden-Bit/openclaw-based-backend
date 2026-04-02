from __future__ import annotations

import os
from pathlib import Path, PurePosixPath


class KnowledgePathError(ValueError):
    """Errore di validazione path in knowledge root."""


def knowledge_root_for_workspace(workspace: str) -> Path:
    base = Path(workspace).expanduser().resolve()
    return (base / "memory" / "knowledge").resolve()


def normalize_relative_path(raw_path: str | None, *, allow_empty: bool = True) -> str:
    raw = (raw_path or "").strip().replace("\\", "/")

    if not raw:
        if allow_empty:
            return ""
        raise KnowledgePathError("path is required")

    if raw.startswith("/"):
        raise KnowledgePathError("absolute paths are not allowed")
    if raw.startswith("~"):
        raise KnowledgePathError("home-relative paths are not allowed")

    path_obj = PurePosixPath(raw)

    cleaned_parts: list[str] = []
    for part in path_obj.parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise KnowledgePathError("path traversal is not allowed")
        if ":" in part:
            # blocca pattern tipo C: su windows o altri alias non desiderati
            raise KnowledgePathError("invalid path segment")
        cleaned_parts.append(part)

    normalized = "/".join(cleaned_parts)
    if not normalized and not allow_empty:
        raise KnowledgePathError("path is required")
    return normalized


def ensure_root_dir(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)


def resolve_under_root(root: Path, rel_path: str, *, must_exist: bool = False) -> Path:
    raw_target = root / rel_path

    # Validate unresolved chain first so symlink segments are rejected explicitly.
    cursor = raw_target
    while True:
        if cursor.exists() and cursor.is_symlink():
            raise KnowledgePathError("symlink paths are not allowed")
        if cursor == root:
            break
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent

    target = raw_target.resolve()

    try:
        target.relative_to(root)
    except ValueError as e:  # outside root
        raise KnowledgePathError("path escapes knowledge root") from e

    if must_exist and not target.exists():
        raise FileNotFoundError(str(target))

    return target


def reject_symlink_chain(path: Path, *, stop_at: Path) -> None:
    current = path
    while True:
        if current.exists() and current.is_symlink():
            raise KnowledgePathError("symlink paths are not allowed")

        if current == stop_at:
            break

        parent = current.parent
        if parent == current:
            break
        current = parent


def reject_hardlinked_file(path: Path) -> None:
    if not path.exists() or path.is_dir():
        return
    stat = path.stat()
    if getattr(stat, "st_nlink", 1) > 1:
        raise KnowledgePathError("hardlinked files are not allowed")


def detect_mime_from_name(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".md"):
        return "text/markdown"
    if lower.endswith(".txt"):
        return "text/plain"
    if lower.endswith(".json"):
        return "application/json"
    if lower.endswith(".csv"):
        return "text/csv"
    return "application/octet-stream"


def validate_allowed_extension(filename: str, allowed_extensions: set[str]) -> None:
    ext = os.path.splitext(filename)[1].lower()
    if not ext or ext not in allowed_extensions:
        raise KnowledgePathError(f"unsupported file extension: {ext or '(none)'}")
