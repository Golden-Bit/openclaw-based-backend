import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.agent_response_language_skill import ensure_response_language_skill_for_agent


def test_ensure_response_language_skill_creates_file(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    skill_path = ensure_response_language_skill_for_agent(str(workspace), user_id="user-1")
    assert skill_path.exists()
    assert skill_path == (workspace / "skills" / "response-language" / "SKILL.md").resolve()

    content = skill_path.read_text(encoding="utf-8")
    assert "name: response-language" in content
    assert "Response Language Skill" in content
    assert "Respond in the same language as the user's latest input message." in content
    assert "Do **not** default to English if the latest input is in another language." in content
    assert "dominant language of that latest input" in content
    assert "brief clarification question in the clearest likely language" in content
    assert "Focus on the most recent user message" in content


def test_ensure_response_language_skill_does_not_overwrite_existing(tmp_path: Path):
    skill_file = tmp_path / "workspace" / "skills" / "response-language" / "SKILL.md"
    skill_file.parent.mkdir(parents=True, exist_ok=True)
    skill_file.write_text("pre-existing", encoding="utf-8")

    out = ensure_response_language_skill_for_agent(str(tmp_path / "workspace"), user_id="user-1")
    assert out == skill_file.resolve()
    assert skill_file.read_text(encoding="utf-8") == "pre-existing"
