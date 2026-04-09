from __future__ import annotations

import hashlib
import re
from pathlib import Path

from app.core.config import settings


def user_namespace(user_id: str) -> str:
    raw = (user_id or "").strip().lower()
    if not raw:
        raw = "anonymous"

    salt = (settings.agent_namespace_salt or "").strip() or "dev-namespace-salt"
    digest = hashlib.sha256(f"{salt}|{raw}".encode("utf-8")).hexdigest()[:24]
    return f"u-{digest}"


def legacy_user_namespace(user_id: str) -> str:
    """Legacy namespace (slug+short-hash) kept for migration compatibility."""
    raw = (user_id or "").strip().lower()
    if not raw:
        raw = "anonymous"

    slug = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-._")
    if not slug:
        slug = "user"

    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"{slug}-{digest}"


def user_workspace_base(user_id: str) -> Path:
    root = Path(settings.agent_workspace_root).expanduser().resolve()
    return (root / user_namespace(user_id)).resolve()


def user_workspace_bases(user_id: str) -> list[Path]:
    primary = user_workspace_base(user_id)
    bases = [primary]

    if settings.agent_namespace_allow_legacy:
        root = Path(settings.agent_workspace_root).expanduser().resolve()
        legacy = (root / legacy_user_namespace(user_id)).resolve()
        if legacy != primary:
            bases.append(legacy)

    return bases


def ensure_user_workspace_base(user_id: str) -> Path:
    base = user_workspace_base(user_id)
    base.mkdir(parents=True, exist_ok=True)
    return base


def normalize_workspace_for_user(user_id: str, workspace_value: str) -> str:
    raw = (workspace_value or "").strip()
    if not raw:
        raise ValueError("workspace cannot be empty")
    if raw.startswith("~"):
        raise ValueError("workspace cannot use home-relative path")

    base = ensure_user_workspace_base(user_id)
    candidate = Path(raw)
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (base / candidate).resolve()

    try:
        resolved.relative_to(base)
    except ValueError as e:
        raise PermissionError("workspace must stay under user workspace namespace") from e

    return resolved.as_posix()


def is_workspace_owned_by_user(user_id: str, workspace_value: str | None) -> bool:
    if not isinstance(workspace_value, str) or not workspace_value.strip():
        return False

    try:
        target = Path(workspace_value).expanduser().resolve()
    except Exception:
        return False

    for base in user_workspace_bases(user_id):
        try:
            target.relative_to(base)
            return True
        except ValueError:
            continue
    return False
