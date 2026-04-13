from __future__ import annotations

import logging
from pathlib import Path

from app.core.agent_ownership import user_namespace
from app.core.config import settings
from app.core.shared_files import normalize_shared_url_prefix


logger = logging.getLogger(__name__)


def _build_public_shared_base_url() -> str:
    base = (settings.bff_public_base_url or "").strip().rstrip("/") or "http://localhost:8000"
    prefix = normalize_shared_url_prefix(settings.shared_files_url_prefix)
    return f"{base}{prefix}"


def _skill_markdown(*, user_id: str) -> str:
    namespace = user_namespace(user_id)
    shared_root = Path(settings.shared_files_root).expanduser().resolve()
    user_share_root = (shared_root / namespace).resolve().as_posix()
    public_base = _build_public_shared_base_url()
    sample_relative = f"{namespace}/exports/<filename>"
    sample_url = f"{public_base}/{sample_relative}"

    return f"""---
name: share-files
description: Save user-downloadable files in shared hosting and reply with markdown links.
---

# Share Files Skill

Use this skill when you need to create files that the user can download via browser link.

## Shared hosting configuration

- Shared filesystem root: `{shared_root.as_posix()}`
- User namespace (hash-only): `{namespace}`
- User writable share root: `{user_share_root}`
- Public URL base: `{public_base}`

## Mandatory rules

1. Write files only under `{user_share_root}/`
2. Never write outside that directory.
3. Build public links as: `{public_base}/<relative_path_from_shared_root>`
4. Always reply with a markdown download link.

## Example

If you save file at:

`{user_share_root}/reports/q1-summary.pdf`

then relative path is:

`{namespace}/reports/q1-summary.pdf`

and public URL is:

`{public_base}/{namespace}/reports/q1-summary.pdf`

Markdown to send:

`[Scarica file]({sample_url})`
"""


def ensure_share_skill_for_agent(workspace: str, *, user_id: str) -> Path:
    ws = Path(workspace).expanduser().resolve()
    skill_dir = (ws / "skills" / "share-files").resolve()

    logger.info(
        "share_skill.bootstrap start user_id=%s workspace_input=%s workspace_resolved=%s skill_dir=%s",
        user_id,
        workspace,
        ws.as_posix(),
        skill_dir.as_posix(),
    )

    skill_dir.mkdir(parents=True, exist_ok=True)

    skill_file = (skill_dir / "SKILL.md").resolve()
    if skill_file.exists() and skill_file.is_file():
        logger.info(
            "share_skill.bootstrap reuse_existing user_id=%s skill_file=%s",
            user_id,
            skill_file.as_posix(),
        )
        return skill_file

    content = _skill_markdown(user_id=user_id)
    skill_file.write_text(content, encoding="utf-8")

    logger.info(
        "share_skill.bootstrap created user_id=%s skill_file=%s",
        user_id,
        skill_file.as_posix(),
    )

    return skill_file
