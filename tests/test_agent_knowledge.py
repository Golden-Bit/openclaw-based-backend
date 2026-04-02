import asyncio
import base64
import io
import sys
from pathlib import Path
from typing import Any

import pytest
from _pytest.monkeypatch import MonkeyPatch
from fastapi import HTTPException
from fastapi import UploadFile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.api.v1.endpoints import knowledge as knowledge_endpoint
from app.schemas.knowledge import (
    KnowledgeFileBase64UploadRequest,
    KnowledgeFilePutRequest,
    KnowledgeFolderCreateRequest,
    KnowledgeFolderMoveRequest,
)


class _FakeWS:
    def __init__(self, responses: dict[str, Any] | None = None):
        self.responses = responses or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call(self, method: str, params: dict[str, Any]):
        self.calls.append((method, params))
        return self.responses.get(method, {})


def _patch_context(monkeypatch: MonkeyPatch, tmp_path: Path, ws: _FakeWS | None = None):
    workspace = tmp_path / "ws"
    root = (workspace / "memory" / "knowledge").resolve()
    root.mkdir(parents=True, exist_ok=True)
    fake_ws = ws or _FakeWS()

    async def _agent_context(agent_id: str):
        return agent_id, fake_ws, str(workspace), root

    monkeypatch.setattr(knowledge_endpoint, "_agent_context", _agent_context)
    return root, fake_ws


def test_create_and_list_tree(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)

    _ = asyncio.run(knowledge_endpoint.create_folder("main", KnowledgeFolderCreateRequest(path="project-a/docs")))
    (root / "project-a" / "docs" / "a.md").write_text("hello", encoding="utf-8")

    res = asyncio.run(knowledge_endpoint.knowledge_tree("main", path="project-a"))

    assert res.path == "project-a"
    assert {i.name for i in res.items} == {"docs"}


def test_prevent_path_traversal(monkeypatch: MonkeyPatch, tmp_path: Path):
    _patch_context(monkeypatch, tmp_path)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(knowledge_endpoint.create_folder("main", KnowledgeFolderCreateRequest(path="../escape")))

    assert exc_info.value.status_code == 400


def test_move_and_delete_folder(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    (root / "one").mkdir(parents=True)

    moved = asyncio.run(
        knowledge_endpoint.move_folder(
            "main",
            KnowledgeFolderMoveRequest(from_path="one", to_path="two/renamed"),
        )
    )
    assert moved.ok is True
    assert (root / "two" / "renamed").exists()

    deleted = asyncio.run(knowledge_endpoint.delete_folder("main", path="two", recursive=True))
    assert deleted.deleted is True
    assert not (root / "two").exists()


def test_delete_non_empty_folder_without_recursive_returns_409(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    (root / "full").mkdir(parents=True)
    (root / "full" / "a.md").write_text("x", encoding="utf-8")

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(knowledge_endpoint.delete_folder("main", path="full", recursive=False))

    assert exc_info.value.status_code == 409


def test_upload_base64_read_and_delete(monkeypatch: MonkeyPatch, tmp_path: Path):
    _patch_context(monkeypatch, tmp_path)

    raw = b"hello knowledge"
    payload = base64.b64encode(raw).decode("ascii")
    created = asyncio.run(
        knowledge_endpoint.upload_file_base64(
            "main",
            KnowledgeFileBase64UploadRequest(
                path="research",
                filename="note.md",
                content_base64=payload,
                overwrite=False,
            ),
        )
    )
    assert created.ok is True
    assert created.path == "research/note.md"

    content = asyncio.run(knowledge_endpoint.read_file_content("main", path="research/note.md"))
    assert content.content_text == "hello knowledge"
    assert content.content_base64 is None

    deleted = asyncio.run(knowledge_endpoint.delete_file("main", path="research/note.md"))
    assert deleted.deleted is True


def test_upload_base64_rejects_invalid_filename(monkeypatch: MonkeyPatch, tmp_path: Path):
    _patch_context(monkeypatch, tmp_path)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            knowledge_endpoint.upload_file_base64(
                "main",
                KnowledgeFileBase64UploadRequest(
                    path="",
                    filename="bad:name.md",
                    content_base64=base64.b64encode(b"x").decode("ascii"),
                    overwrite=False,
                ),
            )
        )

    assert exc_info.value.status_code == 400


def test_replace_file_requires_upsert_when_missing(monkeypatch: MonkeyPatch, tmp_path: Path):
    _patch_context(monkeypatch, tmp_path)
    payload = base64.b64encode(b"x").decode("ascii")

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            knowledge_endpoint.replace_file(
                "main",
                KnowledgeFilePutRequest(path="a/missing.md", content_base64=payload, upsert=False),
            )
        )

    assert exc_info.value.status_code == 404


def test_upload_multipart_overwrite(monkeypatch: MonkeyPatch, tmp_path: Path):
    _patch_context(monkeypatch, tmp_path)

    file1 = UploadFile(filename="k.md", file=io.BytesIO(b"first"))
    _ = asyncio.run(
        knowledge_endpoint.upload_file(
            "main",
            file=file1,
            path="folder",
            filename=None,
            overwrite=False,
        )
    )

    file2 = UploadFile(filename="k.md", file=io.BytesIO(b"second"))
    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            knowledge_endpoint.upload_file(
                "main",
                file=file2,
                path="folder",
                filename=None,
                overwrite=False,
            )
        )
    assert exc_info.value.status_code == 409

    file3 = UploadFile(filename="k.md", file=io.BytesIO(b"second"))
    updated = asyncio.run(
        knowledge_endpoint.upload_file(
            "main",
            file=file3,
            path="folder",
            filename=None,
            overwrite=True,
        )
    )
    assert updated.size_bytes == len(b"second")


def test_reindex_best_effort(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, ws = _patch_context(monkeypatch, tmp_path, ws=_FakeWS(responses={"doctor.memory.status": {"ok": True}}))
    assert root.exists()

    res = asyncio.run(knowledge_endpoint.reindex_knowledge("main"))

    assert res.accepted is True
    assert res.mode == "eventual"
    assert ws.calls == [("doctor.memory.status", {})]


def test_download_file_response(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    (root / "dl").mkdir(parents=True)
    p = root / "dl" / "file.md"
    p.write_text("download-me", encoding="utf-8")

    res = asyncio.run(knowledge_endpoint.download_file("main", path="dl/file.md"))

    assert res.filename == "file.md"
    assert str(res.path).endswith(str(p))


def test_agent_context_rejects_relative_workspace(monkeypatch: MonkeyPatch):
    async def _get_connected_ws():
        return _FakeWS()

    async def _resolve_agent_workspace(_ws, _aid: str) -> str:
        return "relative/path"

    monkeypatch.setattr(knowledge_endpoint.agents_endpoint, "_get_connected_ws", _get_connected_ws)
    monkeypatch.setattr(knowledge_endpoint, "_resolve_agent_workspace", _resolve_agent_workspace)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(knowledge_endpoint._agent_context("main"))

    assert exc_info.value.status_code == 409
