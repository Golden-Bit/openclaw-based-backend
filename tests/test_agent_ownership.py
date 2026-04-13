import sys
from pathlib import Path

from _pytest.monkeypatch import MonkeyPatch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core import agent_ownership
from app.core.config import settings


def test_user_namespace_is_hash_only(monkeypatch: MonkeyPatch):
    monkeypatch.setattr(settings, "agent_namespace_salt", "salt-1")
    ns = agent_ownership.user_namespace("Mario.Rossi")

    assert ns.startswith("u-")
    assert "mario" not in ns
    assert len(ns) == 26


def test_user_workspace_legacy_compat(monkeypatch: MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(settings, "agent_workspace_root", str(tmp_path / "agents"))
    monkeypatch.setattr(settings, "agent_namespace_salt", "salt-1")
    monkeypatch.setattr(settings, "agent_namespace_allow_legacy", True)

    legacy_base = (Path(settings.agent_workspace_root) / agent_ownership.legacy_user_namespace("u1")).resolve()
    legacy_target = (legacy_base / "my-workspace").resolve()
    legacy_target.mkdir(parents=True, exist_ok=True)

    assert agent_ownership.is_workspace_owned_by_user("u1", legacy_target.as_posix()) is True


def test_build_user_scoped_agent_id_adds_user_prefix():
    aid = agent_ownership.build_user_scoped_agent_id("Mario.Rossi", "Sales Bot")

    assert aid.startswith("mario-rossi-")
    assert "sales-bot" in aid
    assert len(aid) <= agent_ownership.MAX_OPENCLAW_AGENT_ID_LENGTH


def test_build_user_scoped_agent_id_respects_max_length():
    aid = agent_ownership.build_user_scoped_agent_id("u" * 80, "x" * 120)

    assert len(aid) <= agent_ownership.MAX_OPENCLAW_AGENT_ID_LENGTH
    assert aid[0].isalnum()


def test_is_agent_id_owned_by_user_checks_prefix():
    own = agent_ownership.build_user_scoped_agent_id("u1", "agent")
    other = agent_ownership.build_user_scoped_agent_id("u2", "agent")

    assert agent_ownership.is_agent_id_owned_by_user("u1", own) is True
    assert agent_ownership.is_agent_id_owned_by_user("u1", other) is False
