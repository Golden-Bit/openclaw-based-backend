import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.agent_file_reference_skill import ensure_file_reference_skill_for_agent


def test_ensure_file_reference_skill_creates_file(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    skill_path = ensure_file_reference_skill_for_agent(str(workspace), user_id="user-1")
    assert skill_path.exists()
    assert skill_path == (workspace / "skills" / "file-reference-disambiguation" / "SKILL.md").resolve()

    content = skill_path.read_text(encoding="utf-8")
    workspace_root = workspace.resolve().as_posix()

    assert "name: file-reference-disambiguation" in content
    assert "Chat Upload Link Handling Skill" in content
    assert workspace_root in content
    assert "/api/v1/uploads/*" in content
    assert "download_url" in content
    assert "public_url" in content
    assert "presigned_get_url" in content
    assert "body.content` plus `sessionKey`" in content
    assert "Do **not** assume hidden attachment bytes" in content
    assert "Treat those links as user-provided file attachments" in content
    assert "Download the file into the workspace before working with it" in content
    assert "default to the most recently uploaded or cited file link in chat" in content
    assert "Do **not** ask for clarification just because older uploaded files also exist" in content
    assert "follow that explicit reference instead of the default" in content
    assert "ask a clarifying question" in content.lower()
    assert "knowledge files" not in content.lower()
    assert "shared-files rules" not in content.lower()



def test_ensure_file_reference_skill_does_not_overwrite_existing(tmp_path: Path):
    skill_file = tmp_path / "workspace" / "skills" / "file-reference-disambiguation" / "SKILL.md"
    skill_file.parent.mkdir(parents=True, exist_ok=True)
    skill_file.write_text("pre-existing", encoding="utf-8")

    out = ensure_file_reference_skill_for_agent(str(tmp_path / "workspace"), user_id="user-1")
    assert out == skill_file.resolve()
    assert skill_file.read_text(encoding="utf-8") == "pre-existing"
