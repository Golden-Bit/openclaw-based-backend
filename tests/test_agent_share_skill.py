import sys
from pathlib import Path

from _pytest.monkeypatch import MonkeyPatch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.agent_ownership import user_namespace
from app.core.agent_share_skill import ensure_share_skill_for_agent
from app.core.config import settings


def test_ensure_share_skill_creates_file(monkeypatch: MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(settings, "shared_files_root", str(tmp_path / "shared"))
    monkeypatch.setattr(settings, "shared_files_url_prefix", "/shared/files")
    monkeypatch.setattr(settings, "bff_public_base_url", "https://api.example.com")
    monkeypatch.setattr(settings, "agent_namespace_salt", "salt-1")

    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    skill_path = ensure_share_skill_for_agent(str(workspace), user_id="user-1")
    assert skill_path.exists()

    content = skill_path.read_text(encoding="utf-8")
    ns = user_namespace("user-1")
    assert "name: share-files" in content
    assert f"User namespace (hash-only): `{ns}`" in content
    assert "https://api.example.com/shared/files" in content


def test_ensure_share_skill_does_not_overwrite_existing(monkeypatch: MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(settings, "shared_files_root", str(tmp_path / "shared"))
    monkeypatch.setattr(settings, "shared_files_url_prefix", "/shared/files")
    monkeypatch.setattr(settings, "bff_public_base_url", "https://api.example.com")

    skill_file = tmp_path / "workspace" / "skills" / "share-files" / "SKILL.md"
    skill_file.parent.mkdir(parents=True, exist_ok=True)
    skill_file.write_text("pre-existing", encoding="utf-8")

    out = ensure_share_skill_for_agent(str(tmp_path / "workspace"), user_id="user-1")
    assert out == skill_file.resolve()
    assert skill_file.read_text(encoding="utf-8") == "pre-existing"
