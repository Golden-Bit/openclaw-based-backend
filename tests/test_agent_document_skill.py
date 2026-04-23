import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.agent_document_skill import ensure_document_skill_for_agent


def test_ensure_document_skill_creates_file(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    skill_path = ensure_document_skill_for_agent(str(workspace), user_id="user-1")
    assert skill_path.exists()
    assert skill_path == (workspace / "skills" / "document-creation-and-manipulation" / "SKILL.md").resolve()

    content = skill_path.read_text(encoding="utf-8")
    assert "name: document-creation-and-manipulation" in content
    assert "Document Creation and Manipulation Skill" in content
    assert "create a temporary Python script inside the workspace" in content
    assert "Delete the temporary Python script as soon as it is no longer needed." in content
    assert "Do **not** force one library for every document type." in content
    assert "python-docx" in content
    assert "docxtpl" in content
    assert "weasyprint" in content
    assert "reportlab" in content
    assert "pypdf" in content
    assert "PyMuPDF" in content
    assert "openpyxl" in content
    assert "python-pptx" in content
    assert "Aim for ChatGPT-like quality in finished documents." in content
    assert "Choose the best-fit library for the requested format and task." in content


def test_ensure_document_skill_does_not_overwrite_existing(tmp_path: Path):
    skill_file = tmp_path / "workspace" / "skills" / "document-creation-and-manipulation" / "SKILL.md"
    skill_file.parent.mkdir(parents=True, exist_ok=True)
    skill_file.write_text("pre-existing", encoding="utf-8")

    out = ensure_document_skill_for_agent(str(tmp_path / "workspace"), user_id="user-1")
    assert out == skill_file.resolve()
    assert skill_file.read_text(encoding="utf-8") == "pre-existing"
