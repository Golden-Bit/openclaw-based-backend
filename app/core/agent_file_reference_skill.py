from __future__ import annotations

import logging
from pathlib import Path


logger = logging.getLogger(__name__)


def _skill_markdown(*, workspace: str) -> str:
    ws = Path(workspace).expanduser().resolve()
    downloads_root = ws.as_posix()

    return f"""---
name: file-reference-disambiguation
description: Treat chat-passed upload links as user-provided file attachments that must be downloaded into the workspace before use, defaulting to the latest uploaded or cited file when the user does not specify one.
---

# Chat Upload Link Handling Skill

Use this skill whenever the user refers to a file passed in chat through a downloadable link.

## What this skill is for

- This skill is only about files the user passes in chat by link.
- Treat those links as user-provided file attachments.
- Download the file into the workspace before working with it.
- Workspace root for downloads: `{downloads_root}`

## Link types you may see

The backend upload flow can expose user file links such as:
- a BFF `download_url` under `/api/v1/uploads/*`
- a direct object `public_url`
- an optional `presigned_get_url`

If the user shares one of these links in chat, treat it as the file reference you should use.

## Important constraints

- Chat messages may persist attachment metadata like `type`, `url`, `mime_type`, and `filename`.
- The BFF WS `agent` call sends the agent only `body.content` plus `sessionKey` when present.
- Do **not** assume hidden attachment bytes, automatic local mounts, or automatic file contents are delivered to you.
- The usable file reference is the download link that appears in chat context.

## Required behavior

1. If the user passes a downloadable upload link in chat, treat it as a file attached by the user in chat.
2. Download that file into the workspace before analyzing, transforming, or reusing it.
3. Preserve the original filename when it is clear from the link or surrounding context.
4. If the user does **not** specify which uploaded file they mean, default to the most recently uploaded or cited file link in chat.
5. If the user explicitly identifies a different uploaded file, follow that explicit reference instead of the default.
6. If multiple upload links are present and the user asks about "the file" without clarifying, interpret that as the latest uploaded or cited file in chat.
7. Ask a clarifying question only when the latest-file default conflicts with the user's wording or when the intended file still cannot be identified safely.

## Clarifying question rule

Do **not** ask for clarification just because older uploaded files also exist in the conversation. Use the latest uploaded or cited file in chat by default.

Ask a clarifying question only when:
- the user explicitly seems to mean an older or differently named file;
- multiple candidate links are present in the same latest message and no single file is the clear target;
- the filename or link reference is still genuinely unclear after applying the latest-file default.

Example questions:
- "Do you mean the latest uploaded file link you just sent in chat?"
- "I see more than one uploaded-file link in your latest message. Which one should I download into the workspace?"
- "You mentioned a different earlier file. Please confirm which uploaded file link I should use before I download it into the workspace."
"""


def ensure_file_reference_skill_for_agent(workspace: str, *, user_id: str) -> Path:
    ws = Path(workspace).expanduser().resolve()
    skill_dir = (ws / "skills" / "file-reference-disambiguation").resolve()

    logger.info(
        (
            "file_reference_skill.bootstrap start user_id=%s workspace_input=%s "
            "workspace_resolved=%s skill_dir=%s"
        ),
        user_id,
        workspace,
        ws.as_posix(),
        skill_dir.as_posix(),
    )

    skill_dir.mkdir(parents=True, exist_ok=True)

    skill_file = (skill_dir / "SKILL.md").resolve()
    if skill_file.exists() and skill_file.is_file():
        logger.info(
            "file_reference_skill.bootstrap reuse_existing user_id=%s skill_file=%s",
            user_id,
            skill_file.as_posix(),
        )
        return skill_file

    content = _skill_markdown(workspace=workspace)
    skill_file.write_text(content, encoding="utf-8")

    logger.info(
        "file_reference_skill.bootstrap created user_id=%s skill_file=%s",
        user_id,
        skill_file.as_posix(),
    )

    return skill_file
