from __future__ import annotations

import hashlib
import re
from pathlib import Path

from app.core.config import settings


MAX_OPENCLAW_AGENT_ID_LENGTH = 64


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


def _sanitize_agent_id_token(raw_value: str, *, fallback: str) -> str:
    raw = (raw_value or "").strip().lower()
    cleaned = re.sub(r"[^a-z0-9_-]+", "-", raw)
    cleaned = re.sub(r"[-_]{2,}", "-", cleaned)
    cleaned = cleaned.strip("-_")
    cleaned = re.sub(r"^[^a-z0-9]+", "", cleaned)
    if not cleaned:
        cleaned = fallback
    if not cleaned[0].isalnum():
        cleaned = f"{fallback}-{cleaned}".strip("-_")
    return cleaned


def user_agent_id_prefix(user_id: str) -> str:
    return _sanitize_agent_id_token(user_id, fallback="user")


def _truncate_agent_id_with_hash(prefix: str, suffix: str) -> str:
    digest = hashlib.sha256(f"{prefix}|{suffix}".encode("utf-8")).hexdigest()[:8]

    max_prefix_len = MAX_OPENCLAW_AGENT_ID_LENGTH - len(digest) - 3  # <prefix>-<suffix>-<hash>
    prefix_part = (prefix[: max(1, max_prefix_len)]).rstrip("-_") or "u"

    remaining_for_suffix = MAX_OPENCLAW_AGENT_ID_LENGTH - len(prefix_part) - len(digest) - 2
    suffix_part = (suffix[: max(1, remaining_for_suffix)]).rstrip("-_") or "a"

    candidate = f"{prefix_part}-{suffix_part}-{digest}"
    if len(candidate) > MAX_OPENCLAW_AGENT_ID_LENGTH:
        candidate = candidate[:MAX_OPENCLAW_AGENT_ID_LENGTH]
    return candidate


def build_user_scoped_agent_id(user_id: str, requested_agent_id: str) -> str:
    prefix = user_agent_id_prefix(user_id)
    suffix = _sanitize_agent_id_token(requested_agent_id, fallback="agent")

    prefixed_marker = f"{prefix}-"
    if suffix.startswith(prefixed_marker):
        suffix = _sanitize_agent_id_token(suffix[len(prefixed_marker) :], fallback="agent")
    if suffix == prefix:
        suffix = "agent"

    candidate = f"{prefix}-{suffix}"
    if len(candidate) <= MAX_OPENCLAW_AGENT_ID_LENGTH:
        return candidate

    return _truncate_agent_id_with_hash(prefix, suffix)


def is_agent_id_owned_by_user(user_id: str, agent_id: str | None) -> bool:
    if not isinstance(agent_id, str):
        return False
    aid = agent_id.strip().lower()
    if not aid:
        return False

    prefix = user_agent_id_prefix(user_id)
    return aid.startswith(f"{prefix}-")


def resolve_requested_agent_id_for_user(user_id: str, requested_agent_id: str) -> str:
    raw = (requested_agent_id or "").strip()
    if not raw:
        raise ValueError("agent_id is required")

    if is_agent_id_owned_by_user(user_id, raw):
        return raw.lower()
    return build_user_scoped_agent_id(user_id, raw)
