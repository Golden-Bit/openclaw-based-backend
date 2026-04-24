from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_MANAGED_START = "<!-- OPENCLAW-BFF:SKILL-ROUTING START -->"
_MANAGED_END = "<!-- OPENCLAW-BFF:SKILL-ROUTING END -->"


def _agents_md_managed_block() -> str:
    return f"""{_MANAGED_START}
## OpenClaw Custom Skills Routing

Read and follow the relevant workspace skill before acting when the request matches one of these cases.

### 1. User-downloadable files
When you generate, export, package, or transform files that the user must download remotely (documents, PDFs, ZIPs, spreadsheets, images, reports, archives, generated assets):

- Read `skills/share-files/SKILL.md`.
- Use only the file-sharing procedure described there.
- Do **not** give the user workspace paths, local filesystem paths, `memory/...` paths, or other internal OpenClaw/backend-only paths as if they were remotely downloadable.
- If a file is generated elsewhere in the workspace, first copy or export it into the shared-files area described in `skills/share-files/SKILL.md`, then return the public markdown link.

### 2. Files passed by the user in chat as links
When the user refers to uploaded files passed in chat through downloadable links:

- Read `skills/file-reference-disambiguation/SKILL.md`.
- Treat those links as user-provided file attachments.
- Download the referenced file into the workspace before using it.
- If the user does not clearly specify which uploaded file they mean, apply the latest-file rule described in that skill.

### 3. Reply language
For every user-facing reply:

- Read `skills/response-language/SKILL.md`.
- Respond in the same language as the user's latest input message unless that skill says clarification is necessary.

### 4. Document creation and manipulation
When the user asks you to create, edit, transform, restyle, merge, split, or otherwise manipulate documents:

- Read `skills/document-creation-and-manipulation/SKILL.md`.
- Follow that skill's workflow for choosing the best-fit library and using temporary Python scripts for non-trivial document tasks.

## Priority rule
If a request matches one of the cases above, consult the referenced skill before proceeding.
If multiple cases apply, follow all relevant skills together.
{_MANAGED_END}
"""


def _upsert_managed_block(existing: str, block: str) -> tuple[str, str]:
    start = existing.find(_MANAGED_START)
    end = existing.find(_MANAGED_END)

    if start != -1 and end != -1 and end >= start:
        end += len(_MANAGED_END)
        replacement = block.rstrip()
        updated = f"{existing[:start].rstrip()}\n\n{replacement}\n\n{existing[end:].lstrip()}".rstrip() + "\n"
        if updated == existing:
            return existing, "unchanged"
        return updated, "replaced"

    trimmed = existing.rstrip()
    if not trimmed:
        created = block.rstrip() + "\n"
        return created, "created"

    updated = f"{trimmed}\n\n{block.rstrip()}\n"
    if updated == existing:
        return existing, "unchanged"
    return updated, "appended"


def ensure_agents_md_for_agent(workspace: str, *, user_id: str) -> Path:
    ws = Path(workspace).expanduser().resolve()
    ws.mkdir(parents=True, exist_ok=True)
    agents_md = (ws / "AGENTS.md").resolve()

    logger.info(
        "agents_md.bootstrap start user_id=%s workspace_input=%s workspace_resolved=%s agents_md=%s",
        user_id,
        workspace,
        ws.as_posix(),
        agents_md.as_posix(),
    )

    block = _agents_md_managed_block()
    if agents_md.exists() and agents_md.is_file():
        existing = agents_md.read_text(encoding="utf-8")
        content, mode = _upsert_managed_block(existing, block)
        if mode == "unchanged":
            logger.info(
                "agents_md.bootstrap reuse_existing user_id=%s agents_md=%s",
                user_id,
                agents_md.as_posix(),
            )
            return agents_md

        agents_md.write_text(content, encoding="utf-8")
        logger.info(
            "agents_md.bootstrap updated user_id=%s agents_md=%s mode=%s",
            user_id,
            agents_md.as_posix(),
            mode,
        )
        return agents_md

    agents_md.write_text(block.rstrip() + "\n", encoding="utf-8")
    logger.info(
        "agents_md.bootstrap created user_id=%s agents_md=%s",
        user_id,
        agents_md.as_posix(),
    )
    return agents_md
