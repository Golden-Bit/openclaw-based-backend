from __future__ import annotations

import logging
from pathlib import Path


logger = logging.getLogger(__name__)


def _skill_markdown() -> str:
    return """---
name: document-creation-and-manipulation
description: Create polished professional documents by choosing the best-fit Python library and using temporary scripts for non-trivial document work.
---

# Document Creation and Manipulation Skill

Use this skill when the user asks you to create, edit, transform, restyle, merge, split, extract, or otherwise manipulate documents.

## Core workflow

1. For non-trivial document generation or manipulation tasks, create a temporary Python script inside the workspace and run that script instead of trying to do the whole job manually.
2. Keep the script focused on the specific document task so it is easy to inspect, rerun, and adjust.
3. Delete the temporary Python script as soon as it is no longer needed.
4. Reuse this script pattern whenever the document task is complex enough that a short one-off command is not reliable.

## Library selection rule

- Choose the best-fit library for the requested format and task.
- Do **not** force one library for every document type.
- Prefer strong libraries with good real-world support for polished output:
  - DOCX authoring/templates: `python-docx`, `docxtpl`
  - PDF generation/layout: `weasyprint`, `reportlab`
  - PDF editing/extraction/merging: `pypdf`, `PyMuPDF`
  - XLSX spreadsheets: `openpyxl`
  - PPTX slide decks: `python-pptx`

## Quality bar

- Aim for ChatGPT-like quality in finished documents.
- Produce polished structure, professional layout, clean hierarchy, and strong readability.
- Use good typography, spacing, alignment, margins, table formatting, and visual consistency whenever the format allows it.
- Prefer a clean final presentation over the fastest possible raw export.

## Practical guidance

- Match the library to the requested output: templated reports, styled PDFs, spreadsheet editing, slide generation, or PDF post-processing may need different tools.
- When a document needs higher polish, use the library that gives you better layout and formatting control for that format.
- Keep intermediate automation files temporary; the deliverable document should remain, but helper scripts should be removed after use unless the user explicitly asks to keep them.
"""


def ensure_document_skill_for_agent(workspace: str, *, user_id: str) -> Path:
    ws = Path(workspace).expanduser().resolve()
    skill_dir = (ws / "skills" / "document-creation-and-manipulation").resolve()

    logger.info(
        (
            "document_skill.bootstrap start user_id=%s workspace_input=%s "
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
            "document_skill.bootstrap reuse_existing user_id=%s skill_file=%s",
            user_id,
            skill_file.as_posix(),
        )
        return skill_file

    content = _skill_markdown()
    skill_file.write_text(content, encoding="utf-8")

    logger.info(
        "document_skill.bootstrap created user_id=%s skill_file=%s",
        user_id,
        skill_file.as_posix(),
    )

    return skill_file
