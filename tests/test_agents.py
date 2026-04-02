import asyncio
import sys
from typing import Any, Dict, Optional
from pathlib import Path

import pytest
from fastapi import HTTPException
from _pytest.monkeypatch import MonkeyPatch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.api.v1.endpoints import agents as agents_endpoint
from app.schemas.agents import AgentUpdateRequest


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


def test_map_ws_error_unsupported_method():
    exc = Exception("method_not_found: agents.files.list")
    err = agents_endpoint._map_ws_error("agents.files.list", exc)
    assert err.status_code == 501


def test_map_ws_error_missing_scope():
    exc = Exception("forbidden: missing scope operator.admin")
    err = agents_endpoint._map_ws_error("agents.delete", exc)
    assert err.status_code == 503


def test_list_agents_success(monkeypatch: MonkeyPatch):
    ws = _FakeWS(
        responses={
            "agents.list": {
                "defaultId": "main",
                "mainKey": "key-1",
                "scope": "operator.read",
                "agents": [
                    {
                        "id": "main",
                        "name": "Main",
                        "workspace": "/tmp/ws",
                        "model": {"primary": "gpt-4.1", "fallbacks": ["gpt-4o-mini"]},
                    },
                    {"id": "other", "name": "Other", "workspace": "/tmp/other", "model": {}},
                ],
            }
        }
    )
    _patch_ws(monkeypatch, ws)

    res = asyncio.run(agents_endpoint.list_agents())

    assert res.default_agent_id == "main"
    assert res.main_key == "key-1"
    assert len(res.items) == 2
    assert res.items[0].is_default is True
    assert res.items[0].model == "gpt-4.1"
    assert res.items[0].model_fallbacks == ["gpt-4o-mini"]
    assert ws.calls == [("agents.list", {})]


def test_get_agent_with_identity_and_files(monkeypatch: MonkeyPatch):
    ws = _FakeWS(
        responses={
            "agents.list": {
                "defaultId": "main",
                "agents": [{"id": "main", "name": "Main", "workspace": "/tmp/ws", "model": {}}],
            },
            "agent.identity.get": {"agentId": "main", "avatarUrl": "https://example/avatar.png"},
            "agents.files.list": {"files": [{"id": "f1", "name": "bootstrap.md"}]},
        }
    )
    _patch_ws(monkeypatch, ws)

    res = asyncio.run(agents_endpoint.get_agent("main", include_files=True))

    assert res.agent_id == "main"
    assert res.identity is not None
    assert res.identity["agent_id"] == "main"
    assert res.identity["avatar_url"] == "https://example/avatar.png"
    assert res.files == [{"id": "f1", "name": "bootstrap.md"}]
    assert res.warnings == []


def test_get_agent_returns_404_when_missing(monkeypatch: MonkeyPatch):
    ws = _FakeWS(responses={"agents.list": {"defaultId": "main", "agents": [{"id": "main"}]}})
    _patch_ws(monkeypatch, ws)

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(agents_endpoint.get_agent("missing", include_files=False))

    assert exc_info.value.status_code == 404


def test_update_agent_requires_at_least_one_field(monkeypatch: MonkeyPatch):
    ws = _FakeWS()
    _patch_ws(monkeypatch, ws)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(agents_endpoint.update_agent("main", AgentUpdateRequest()))

    assert exc_info.value.status_code == 400


def test_update_agent_success(monkeypatch: MonkeyPatch):
    ws = _FakeWS(responses={"agents.update": {"ok": True}})
    _patch_ws(monkeypatch, ws)

    res = asyncio.run(
        agents_endpoint.update_agent(
            "main",
            AgentUpdateRequest(name="Main Agent", model="gpt-4.1"),
        )
    )

    assert res.updated is True
    assert res.agent_id == "main"
    assert ws.calls == [
        (
            "agents.update",
            {
                "agentId": "main",
                "name": "Main Agent",
                "model": "gpt-4.1",
            },
        )
    ]


def test_delete_agent_success(monkeypatch: MonkeyPatch):
    ws = _FakeWS(responses={"agents.delete": {"removedBindings": 3}})
    _patch_ws(monkeypatch, ws)

    res = asyncio.run(agents_endpoint.delete_agent("main", delete_files=False))

    assert res.deleted is True
    assert res.agent_id == "main"
    assert res.removed_bindings == 3
    assert ws.calls == [("agents.delete", {"agentId": "main", "deleteFiles": False})]
