from __future__ import annotations

import os
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


MARKDOWN_EXTENSION = ".md"
TEXT_KNOWLEDGE_EXTENSIONS = {".txt", ".json", ".csv"}
DOCLING_KNOWLEDGE_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".pptx"}
PAIRABLE_KNOWLEDGE_EXTENSIONS = TEXT_KNOWLEDGE_EXTENSIONS | DOCLING_KNOWLEDGE_EXTENSIONS
ALLOWED_KNOWLEDGE_EXTENSIONS = {MARKDOWN_EXTENSION} | PAIRABLE_KNOWLEDGE_EXTENSIONS


class KnowledgePathError(ValueError):
    """Errore di validazione path in knowledge root."""


@dataclass(frozen=True)
class KnowledgeWritePlan:
    requested_filename: str
    original_filename: str
    markdown_filename: str | None
    collision_rule: str

    @property
    def stores_generated_markdown(self) -> bool:
        return self.markdown_filename is not None


@dataclass(frozen=True)
class KnowledgeMutationPlan:
    requested_filename: str
    managed_original_filename: str | None
    managed_markdown_filename: str | None
    classification: str

    @property
    def is_managed_pair_member(self) -> bool:
        return self.managed_original_filename is not None and self.managed_markdown_filename is not None

    @property
    def is_managed_markdown(self) -> bool:
        return self.is_managed_pair_member and is_markdown_filename(self.requested_filename)

    @property
    def delete_filenames(self) -> tuple[str, ...]:
        if self.is_managed_pair_member:
            return (self.managed_original_filename or self.requested_filename, self.managed_markdown_filename or self.requested_filename)
        return (self.requested_filename,)


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


def knowledge_file_extension(filename: str) -> str:
    return os.path.splitext(filename)[1].lower()


def is_markdown_filename(filename: str) -> bool:
    return knowledge_file_extension(filename) == MARKDOWN_EXTENSION


def markdown_sibling_filename(filename: str) -> str:
    if is_markdown_filename(filename):
        raise KnowledgePathError("markdown files do not use generated markdown siblings")
    stem = Path(filename).stem
    return f"{stem}{MARKDOWN_EXTENSION}"


def incremented_filename(filename: str, index: int) -> str:
    if index < 1:
        raise ValueError("index must be >= 1")
    path = Path(filename)
    return f"{path.stem}-{index}{path.suffix}"


def pairable_original_filenames_for_markdown(filename: str) -> tuple[str, ...]:
    if not is_markdown_filename(filename):
        raise KnowledgePathError("only markdown filenames have pairable original siblings")
    stem = Path(filename).stem
    return tuple(f"{stem}{ext}" for ext in sorted(PAIRABLE_KNOWLEDGE_EXTENSIONS))


def plan_knowledge_mutation(folder: Path, filename: str) -> KnowledgeMutationPlan:
    ext = knowledge_file_extension(filename)
    if ext in PAIRABLE_KNOWLEDGE_EXTENSIONS:
        return KnowledgeMutationPlan(
            requested_filename=filename,
            managed_original_filename=filename,
            managed_markdown_filename=markdown_sibling_filename(filename),
            classification="managed_original",
        )

    if is_markdown_filename(filename):
        matches = [
            candidate
            for candidate in pairable_original_filenames_for_markdown(filename)
            if (folder / candidate).exists()
        ]
        if len(matches) > 1:
            raise KnowledgePathError("multiple same-stem original files reserve this markdown path")
        if matches:
            return KnowledgeMutationPlan(
                requested_filename=filename,
                managed_original_filename=matches[0],
                managed_markdown_filename=filename,
                classification="managed_markdown_existing" if (folder / filename).exists() else "managed_markdown_reserved",
            )
        return KnowledgeMutationPlan(
            requested_filename=filename,
            managed_original_filename=None,
            managed_markdown_filename=None,
            classification="standalone_markdown",
        )

    return KnowledgeMutationPlan(
        requested_filename=filename,
        managed_original_filename=None,
        managed_markdown_filename=None,
        classification="direct_file",
    )


def plan_knowledge_write(folder: Path, filename: str) -> KnowledgeWritePlan:
    if is_markdown_filename(filename):
        return KnowledgeWritePlan(
            requested_filename=filename,
            original_filename=filename,
            markdown_filename=None,
            collision_rule="direct_markdown",
        )

    original_path = folder / filename
    markdown_filename = markdown_sibling_filename(filename)
    markdown_path = folder / markdown_filename

    original_exists = original_path.exists()
    markdown_exists = markdown_path.exists()

    if original_exists and markdown_exists:
        return KnowledgeWritePlan(
            requested_filename=filename,
            original_filename=filename,
            markdown_filename=markdown_filename,
            collision_rule="managed_pair_update",
        )

    if markdown_exists and not original_exists:
        index = 1
        while True:
            candidate_original = incremented_filename(filename, index)
            candidate_markdown = markdown_sibling_filename(candidate_original)
            if not (folder / candidate_original).exists() and not (folder / candidate_markdown).exists():
                return KnowledgeWritePlan(
                    requested_filename=filename,
                    original_filename=candidate_original,
                    markdown_filename=candidate_markdown,
                    collision_rule="incremented_pair",
                )
            index += 1

    if original_exists:
        return KnowledgeWritePlan(
            requested_filename=filename,
            original_filename=filename,
            markdown_filename=markdown_filename,
            collision_rule="original_only_update",
        )

    return KnowledgeWritePlan(
        requested_filename=filename,
        original_filename=filename,
        markdown_filename=markdown_filename,
        collision_rule="new_pair",
    )


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
    if lower.endswith(".pdf"):
        return "application/pdf"
    if lower.endswith(".docx"):
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    if lower.endswith(".xlsx"):
        return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    if lower.endswith(".pptx"):
        return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    return "application/octet-stream"


def validate_allowed_extension(filename: str, allowed_extensions: set[str]) -> None:
    ext = knowledge_file_extension(filename)
    if not ext or ext not in allowed_extensions:
        raise KnowledgePathError(f"unsupported file extension: {ext or '(none)'}")


def atomic_write_files(writes: list[tuple[Path, bytes]]) -> None:
    staged: list[tuple[Path, Path]] = []
    backups: list[tuple[Path, Path]] = []
    committed: list[Path] = []

    try:
        for target, data in writes:
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
            tmp_path = Path(tmp_name)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            staged.append((target, tmp_path))

        for target, _tmp_path in staged:
            if target.exists():
                if target.is_dir():
                    raise IsADirectoryError(str(target))
                backup_path = target.with_name(f".{target.name}.{uuid.uuid4().hex}.bak")
                os.replace(target, backup_path)
                backups.append((target, backup_path))

        for target, tmp_path in staged:
            os.replace(tmp_path, target)
            committed.append(target)
    except Exception:
        for target in reversed(committed):
            try:
                if target.exists():
                    target.unlink()
            except OSError:
                pass

        for target, backup_path in reversed(backups):
            try:
                os.replace(backup_path, target)
            except OSError:
                pass
        raise
    else:
        for _target, backup_path in backups:
            if backup_path.exists():
                backup_path.unlink()
    finally:
        for _target, tmp_path in staged:
            if tmp_path.exists():
                tmp_path.unlink()


def atomic_delete_files(paths: list[Path]) -> None:
    backups: list[tuple[Path, Path]] = []
    original_contents: dict[str, bytes] = {}
    seen: set[str] = set()

    try:
        for target in paths:
            key = str(target)
            if key in seen or not target.exists():
                continue
            seen.add(key)
            if target.is_dir():
                raise IsADirectoryError(str(target))
            original_contents[key] = target.read_bytes()
            backup_path = target.with_name(f".{target.name}.{uuid.uuid4().hex}.del")
            os.replace(target, backup_path)
            backups.append((target, backup_path))

        for _target, backup_path in backups:
            backup_path.unlink()
    except Exception:
        for target, backup_path in reversed(backups):
            try:
                if backup_path.exists() and not target.exists():
                    os.replace(backup_path, target)
                elif not backup_path.exists() and not target.exists() and str(target) in original_contents:
                    target.write_bytes(original_contents[str(target)])
            except OSError:
                pass
        raise
