import asyncio
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pytest
from _pytest.monkeypatch import MonkeyPatch
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.api.v1.endpoints import agents as agents_endpoint
from app.core.agent_ownership import build_user_scoped_agent_id, normalize_workspace_for_user
from app.core.security import AuthenticatedUser
from app.schemas.agents import AgentCreateRequest, AgentUpdateRequest


class _FakeWS:
    def __init__(
        self,
        responses: Optional[Dict[str, Any]] = None,
        errors: Optional[Dict[str, Exception]] = None,
    ):
        self._responses: Dict[str, Any] = responses or {}
        self._errors: Dict[str, Exception] = errors or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call(self, method: str, params: dict[str, Any]):
        self.calls.append((method, params))
        if method in self._errors:
            raise self._errors[method]
        return self._responses.get(method, {})


def _patch_ws(monkeypatch: MonkeyPatch, ws: _FakeWS):
    async def _get_connected_ws():
        return ws

    monkeypatch.setattr(agents_endpoint, "_get_connected_ws", _get_connected_ws)


def _patch_skill_bootstrap(monkeypatch: MonkeyPatch, *, fail: bool = False):
    calls: list[tuple[str, str]] = []

    def _ensure_share_skill_for_agent(workspace: str, *, user_id: str):
        calls.append((workspace, user_id))
        if fail:
            raise RuntimeError("bootstrap failed")
        return Path(workspace) / "skills" / "share-files" / "SKILL.md"

    monkeypatch.setattr(agents_endpoint, "ensure_share_skill_for_agent", _ensure_share_skill_for_agent)
    return calls


def _user(uid: str = "u1") -> AuthenticatedUser:
    return AuthenticatedUser(user_id=uid, claims={})


def test_map_ws_error_unsupported_method():
    exc = Exception("method_not_found: agents.files.list")
    err = agents_endpoint._map_ws_error("agents.files.list", exc)
    assert err.status_code == 501


def test_map_ws_error_missing_scope():
    exc = Exception("forbidden: missing scope operator.admin")
    err = agents_endpoint._map_ws_error("agents.delete", exc)
    assert err.status_code == 503


def test_list_agents_success(monkeypatch: MonkeyPatch):
    owned_ws = normalize_workspace_for_user("u1", "ws")
    other_ws = normalize_workspace_for_user("u2", "ws")
    own_agent_id = build_user_scoped_agent_id("u1", "main")
    other_agent_id = build_user_scoped_agent_id("u2", "other")

    ws = _FakeWS(
        responses={
            "agents.list": {
                "defaultId": own_agent_id,
                "mainKey": "key-1",
                "scope": "operator.read",
                "agents": [
                    {
                        "id": own_agent_id,
                        "name": "Main",
                        "workspace": owned_ws,
                        "model": {"primary": "gpt-4.1", "fallbacks": ["gpt-4o-mini"]},
                    },
                    {"id": other_agent_id, "name": "Other", "workspace": other_ws, "model": {}},
                ],
            }
        }
    )
    _patch_ws(monkeypatch, ws)

    res = asyncio.run(agents_endpoint.list_agents(_user("u1")))

    assert res.default_agent_id == own_agent_id
    assert res.main_key == "key-1"
    assert len(res.items) == 1
    assert res.items[0].agent_id == own_agent_id
    assert res.items[0].is_default is True
    assert res.items[0].model == "gpt-4.1"
    assert res.items[0].model_fallbacks == ["gpt-4o-mini"]
    assert ws.calls == [("agents.list", {})]


def test_list_agents_uses_identity_name_and_string_model(monkeypatch: MonkeyPatch):
    own_agent_id = build_user_scoped_agent_id("u1", "main")
    owned_ws = normalize_workspace_for_user("u1", "ws")

    ws = _FakeWS(
        responses={
            "agents.list": {
                "defaultId": own_agent_id,
                "mainKey": "key-1",
                "scope": "per-sender",
                "agents": [
                    {
                        "id": own_agent_id,
                        "name": "",
                        "identity": {"name": "Main from identity"},
                        "workspace": owned_ws,
                        "model": "openai:gpt-4.1",
                    }
                ],
            }
        }
    )
    _patch_ws(monkeypatch, ws)

    res = asyncio.run(agents_endpoint.list_agents(_user("u1")))

    assert len(res.items) == 1
    assert res.items[0].name == "Main from identity"
    assert res.items[0].model == "openai:gpt-4.1"


def test_create_agent_success(monkeypatch: MonkeyPatch):
    expected_ws = normalize_workspace_for_user("u1", "a1")
    expected_agent_id = build_user_scoped_agent_id("u1", "Agent 1")

    ws = _FakeWS(
        responses={
            "agents.create": {
                "ok": True,
                "agentId": expected_agent_id,
                "name": expected_agent_id,
                "workspace": "/tmp/a1",
            }
        }
    )
    _patch_ws(monkeypatch, ws)
    skill_calls = _patch_skill_bootstrap(monkeypatch)

    res = asyncio.run(
        agents_endpoint.create_agent(
            AgentCreateRequest(name="Agent 1", workspace="a1", emoji="🤖"),
            _user("u1"),
        )
    )

    assert res.created is True
    assert res.agent_id == expected_agent_id
    assert res.name == expected_agent_id
    assert res.workspace == "/tmp/a1"
    assert ws.calls == [
        (
            "agents.create",
            {
                "name": expected_agent_id,
                "workspace": expected_ws,
                "emoji": "🤖",
            },
        )
    ]
    assert skill_calls == [("/tmp/a1", "u1")]


def test_create_agent_uses_user_scoped_id_even_with_long_input(monkeypatch: MonkeyPatch):
    long_name = "Agent " + ("X" * 200)
    scoped = build_user_scoped_agent_id("u1", long_name)
    ws = _FakeWS(responses={"agents.create": {"ok": True, "agentId": scoped, "workspace": normalize_workspace_for_user("u1", "a1")}})
    _patch_ws(monkeypatch, ws)
    _ = _patch_skill_bootstrap(monkeypatch)

    res = asyncio.run(
        agents_endpoint.create_agent(
            AgentCreateRequest(name=long_name, workspace="a1"),
            _user("u1"),
        )
    )

    assert len(res.agent_id or "") <= 64
    assert (res.agent_id or "").startswith("u1-")


def test_create_agent_rolls_back_when_returned_agent_id_is_not_owned(monkeypatch: MonkeyPatch):
    expected_ws = normalize_workspace_for_user("u1", "a1")
    ws = _FakeWS(
        responses={
            "agents.create": {"ok": True, "agentId": "u2-foreign", "workspace": expected_ws},
            "agents.delete": {"ok": True},
        }
    )
    _patch_ws(monkeypatch, ws)
    _ = _patch_skill_bootstrap(monkeypatch)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            agents_endpoint.create_agent(
                AgentCreateRequest(name="Agent 1", workspace="a1"),
                _user("u1"),
            )
        )

    assert exc_info.value.status_code == 502
    assert ws.calls[-1] == ("agents.delete", {"agentId": "u2-foreign", "deleteFiles": True})


def test_create_agent_rejects_empty_workspace(monkeypatch: MonkeyPatch):
    ws = _FakeWS()
    _patch_ws(monkeypatch, ws)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            agents_endpoint.create_agent(
                AgentCreateRequest(name="Agent 1", workspace="   "),
                _user("u1"),
            )
        )

    assert exc_info.value.status_code == 400


def test_create_agent_rolls_back_when_skill_bootstrap_fails(monkeypatch: MonkeyPatch):
    scoped_id = build_user_scoped_agent_id("u1", "Agent 2")
    ws = _FakeWS(
        responses={
            "agents.create": {
                "ok": True,
                "agentId": scoped_id,
                "name": scoped_id,
                "workspace": normalize_workspace_for_user("u1", "a2"),
            },
            "agents.delete": {"ok": True},
        }
    )
    _patch_ws(monkeypatch, ws)
    _ = _patch_skill_bootstrap(monkeypatch, fail=True)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            agents_endpoint.create_agent(
                AgentCreateRequest(name="Agent 2", workspace="a2"),
                _user("u1"),
            )
        )

    assert exc_info.value.status_code == 500
    assert ws.calls[0][0] == "agents.create"
    assert ws.calls[1] == ("agents.delete", {"agentId": scoped_id, "deleteFiles": True})


def test_create_agent_rejects_foreign_absolute_workspace(monkeypatch: MonkeyPatch):
    ws = _FakeWS()
    _patch_ws(monkeypatch, ws)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            agents_endpoint.create_agent(
                AgentCreateRequest(name="Agent 1", workspace="/tmp/foreign"),
                _user("u1"),
            )
        )

    assert exc_info.value.status_code == 403


def test_get_agent_with_identity_and_files(monkeypatch: MonkeyPatch):
    own_agent_id = build_user_scoped_agent_id("u1", "main")
    owned_ws = normalize_workspace_for_user("u1", "ws")

    ws = _FakeWS(
        responses={
            "agents.list": {
                "defaultId": own_agent_id,
                "agents": [{"id": own_agent_id, "name": "Main", "workspace": owned_ws, "model": {}}],
            },
            "agent.identity.get": {"agentId": own_agent_id, "avatarUrl": "https://example/avatar.png"},
            "agents.files.list": {"files": [{"id": "f1", "name": "bootstrap.md"}]},
        }
    )
    _patch_ws(monkeypatch, ws)

    res = asyncio.run(agents_endpoint.get_agent("main", include_files=True, user=_user("u1")))

    assert res.agent_id == own_agent_id
    assert res.identity is not None
    assert res.identity["agent_id"] == own_agent_id
    assert res.identity["avatar_url"] == "https://example/avatar.png"
    assert res.files == [{"id": "f1", "name": "bootstrap.md"}]
    assert res.warnings == []


def test_get_agent_returns_404_when_missing(monkeypatch: MonkeyPatch):
    own_agent_id = build_user_scoped_agent_id("u1", "main")
    ws = _FakeWS(responses={"agents.list": {"defaultId": own_agent_id, "agents": [{"id": own_agent_id}]}})
    _patch_ws(monkeypatch, ws)

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(agents_endpoint.get_agent("missing", include_files=False, user=_user("u1")))

    assert exc_info.value.status_code == 404


def test_update_agent_requires_at_least_one_field(monkeypatch: MonkeyPatch):
    own_agent_id = build_user_scoped_agent_id("u1", "main")
    ws = _FakeWS(responses={"agents.list": {"defaultId": own_agent_id, "agents": [{"id": own_agent_id, "workspace": normalize_workspace_for_user('u1', 'ws')}]}})
    _patch_ws(monkeypatch, ws)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(agents_endpoint.update_agent("main", AgentUpdateRequest(), _user("u1")))

    assert exc_info.value.status_code == 400


def test_update_agent_success(monkeypatch: MonkeyPatch):
    own_agent_id = build_user_scoped_agent_id("u1", "main")
    ws = _FakeWS(
        responses={
            "agents.list": {"defaultId": own_agent_id, "agents": [{"id": own_agent_id, "workspace": normalize_workspace_for_user('u1', 'ws')}]},
            "agents.update": {"ok": True},
        }
    )
    _patch_ws(monkeypatch, ws)

    res = asyncio.run(
        agents_endpoint.update_agent(
            "main",
            AgentUpdateRequest(name="Main Agent", model="gpt-4.1"),
            _user("u1"),
        )
    )

    assert res.updated is True
    assert res.agent_id == own_agent_id
    assert ws.calls == [
        ("agents.list", {}),
        (
            "agents.update",
            {
                "agentId": own_agent_id,
                "name": "Main Agent",
                "model": "gpt-4.1",
            },
        )
    ]


def test_delete_agent_success(monkeypatch: MonkeyPatch):
    own_agent_id = build_user_scoped_agent_id("u1", "main")
    ws = _FakeWS(
        responses={
            "agents.list": {"defaultId": own_agent_id, "agents": [{"id": own_agent_id, "workspace": normalize_workspace_for_user('u1', 'ws')}]},
            "agents.delete": {"removedBindings": 3},
        }
    )
    _patch_ws(monkeypatch, ws)

    res = asyncio.run(agents_endpoint.delete_agent("main", delete_files=False, user=_user("u1")))

    assert res.deleted is True
    assert res.agent_id == own_agent_id
    assert res.removed_bindings == 3
    assert ws.calls == [
        ("agents.list", {}),
        ("agents.delete", {"agentId": own_agent_id, "deleteFiles": False}),
    ]


def test_update_agent_returns_404_when_agent_id_not_owned(monkeypatch: MonkeyPatch):
    ws = _FakeWS(
        responses={
            "agents.list": {"defaultId": "u2-main", "agents": [{"id": "u2-main", "workspace": normalize_workspace_for_user('u2', 'ws')}]},
        }
    )
    _patch_ws(monkeypatch, ws)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            agents_endpoint.update_agent(
                "main",
                AgentUpdateRequest(name="new"),
                _user("u1"),
            )
        )

    assert exc_info.value.status_code == 404


def test_get_agent_returns_404_when_agent_id_not_owned(monkeypatch: MonkeyPatch):
    ws = _FakeWS(
        responses={
            "agents.list": {
                "defaultId": "u2-main",
                "agents": [{"id": "u2-main", "workspace": normalize_workspace_for_user("u2", "ws")}],
            }
        }
    )
    _patch_ws(monkeypatch, ws)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(agents_endpoint.get_agent("main", include_files=False, user=_user("u1")))

    assert exc_info.value.status_code == 404


def test_list_and_get_ignore_workspace_when_agent_id_owned(monkeypatch: MonkeyPatch):
    own_agent_id = build_user_scoped_agent_id("u1", "a-1")
    ws = _FakeWS(
        responses={
            "agents.list": {
                "defaultId": own_agent_id,
                "agents": [
                    {"id": own_agent_id, "name": "Agent 1"},
                    {"id": build_user_scoped_agent_id("u2", "agent-2"), "name": "Agent 2"},
                ],
            },
            "agent.identity.get": {},
        }
    )
    _patch_ws(monkeypatch, ws)

    list_res = asyncio.run(agents_endpoint.list_agents(_user("u1")))
    get_res = asyncio.run(agents_endpoint.get_agent("a-1", include_files=False, user=_user("u1")))

    assert len(list_res.items) == 1
    assert {item.agent_id for item in list_res.items} == {own_agent_id}
    assert get_res.agent_id == own_agent_id
