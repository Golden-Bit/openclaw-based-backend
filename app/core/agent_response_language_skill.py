from __future__ import annotations

import logging
from pathlib import Path


logger = logging.getLogger(__name__)


def _skill_markdown() -> str:
    return """---
name: response-language
description: Answer in the same language as the user's latest input message.
---

# Response Language Skill

Use this skill on every user-facing reply.

## Required behavior

1. Respond in the same language as the user's latest input message.
2. Do **not** default to English if the latest input is in another language.
3. If the latest input is mostly one language with a few foreign words, respond in the dominant language of that latest input.
4. If the latest input is truly ambiguous or mixed and the language choice materially matters, ask a brief clarification question in the clearest likely language.

## Quick guidance

- Focus on the most recent user message, not older turns.
- Keep the reply language aligned with that latest input even if earlier messages used a different language.
- If the latest input mixes languages but one is clearly dominant, use that dominant language.
- If no dominant language is clear and the choice could confuse the user, ask a short clarifying question before proceeding.
"""


def ensure_response_language_skill_for_agent(workspace: str, *, user_id: str) -> Path:
    ws = Path(workspace).expanduser().resolve()
    skill_dir = (ws / 'skills' / 'response-language').resolve()

    logger.info(
        (
            'response_language_skill.bootstrap start user_id=%s workspace_input=%s '
            'workspace_resolved=%s skill_dir=%s'
        ),
        user_id,
        workspace,
        ws.as_posix(),
        skill_dir.as_posix(),
    )

    skill_dir.mkdir(parents=True, exist_ok=True)

    skill_file = (skill_dir / 'SKILL.md').resolve()
    if skill_file.exists() and skill_file.is_file():
        logger.info(
            'response_language_skill.bootstrap reuse_existing user_id=%s skill_file=%s',
            user_id,
            skill_file.as_posix(),
        )
        return skill_file

    content = _skill_markdown()
    skill_file.write_text(content, encoding='utf-8')

    logger.info(
        'response_language_skill.bootstrap created user_id=%s skill_file=%s',
        user_id,
        skill_file.as_posix(),
    )

    return skill_file
