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
from app.core.knowledge_conversion import KnowledgeConversionError
from app.core.security import AuthenticatedUser
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


def _user(uid: str = "u1") -> AuthenticatedUser:
    return AuthenticatedUser(user_id=uid, claims={})


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _patch_context(monkeypatch: MonkeyPatch, tmp_path: Path, ws: _FakeWS | None = None):
    workspace = tmp_path / "ws"
    root = (workspace / "memory" / "knowledge").resolve()
    root.mkdir(parents=True, exist_ok=True)
    fake_ws = ws or _FakeWS()

    async def _agent_context(agent_id: str, user: AuthenticatedUser):
        return agent_id, fake_ws, str(workspace), root

    monkeypatch.setattr(knowledge_endpoint, "_agent_context", _agent_context)
    return root, fake_ws


def test_create_and_list_tree(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)

    _ = asyncio.run(knowledge_endpoint.create_folder("main", KnowledgeFolderCreateRequest(path="project-a/docs"), _user("u1")))
    (root / "project-a" / "docs" / "a.md").write_text("hello", encoding="utf-8")

    res = asyncio.run(knowledge_endpoint.knowledge_tree("main", path="project-a", user=_user("u1")))

    assert res.path == "project-a"
    assert {i.name for i in res.items} == {"docs"}


def test_prevent_path_traversal(monkeypatch: MonkeyPatch, tmp_path: Path):
    _patch_context(monkeypatch, tmp_path)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(knowledge_endpoint.create_folder("main", KnowledgeFolderCreateRequest(path="../escape"), _user("u1")))

    assert exc_info.value.status_code == 400


def test_move_and_delete_folder(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    (root / "one").mkdir(parents=True)

    moved = asyncio.run(
        knowledge_endpoint.move_folder(
            "main",
            KnowledgeFolderMoveRequest(from_path="one", to_path="two/renamed"),
            _user("u1"),
        )
    )
    assert moved.ok is True
    assert (root / "two" / "renamed").exists()

    deleted = asyncio.run(knowledge_endpoint.delete_folder("main", path="two", recursive=True, user=_user("u1")))
    assert deleted.deleted is True
    assert not (root / "two").exists()


def test_delete_non_empty_folder_without_recursive_returns_409(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    (root / "full").mkdir(parents=True)
    (root / "full" / "a.md").write_text("x", encoding="utf-8")

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(knowledge_endpoint.delete_folder("main", path="full", recursive=False, user=_user("u1")))

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
            _user("u1"),
        )
    )
    assert created.ok is True
    assert created.path == "research/note.md"

    content = asyncio.run(knowledge_endpoint.read_file_content("main", path="research/note.md", user=_user("u1")))
    assert content.content_text == "hello knowledge"
    assert content.content_base64 is None

    deleted = asyncio.run(knowledge_endpoint.delete_file("main", path="research/note.md", user=_user("u1")))
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
                _user("u1"),
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
                _user("u1"),
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
            user=_user("u1"),
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
                user=_user("u1"),
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
            user=_user("u1"),
        )
    )
    assert updated.size_bytes == len(b"second")


def test_reindex_best_effort(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, ws = _patch_context(monkeypatch, tmp_path, ws=_FakeWS(responses={"doctor.memory.status": {"ok": True}}))
    assert root.exists()

    res = asyncio.run(knowledge_endpoint.reindex_knowledge("main", _user("u1")))

    assert res.accepted is True
    assert res.mode == "eventual"
    assert ws.calls == [("doctor.memory.status", {})]


def test_download_file_response(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    (root / "dl").mkdir(parents=True)
    p = root / "dl" / "file.md"
    p.write_text("download-me", encoding="utf-8")

    res = asyncio.run(knowledge_endpoint.download_file("main", path="dl/file.md", user=_user("u1")))

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
        _ = asyncio.run(knowledge_endpoint._agent_context("main", _user("u1")))

    assert exc_info.value.status_code == 409


def test_agent_context_accepts_absolute_workspace_when_agent_id_owned(monkeypatch: MonkeyPatch, tmp_path: Path):
    foreign_workspace = str((tmp_path / "foreign").resolve())

    async def _get_connected_ws():
        return _FakeWS()

    async def _resolve_agent_workspace(_ws, _aid: str) -> str:
        return foreign_workspace

    monkeypatch.setattr(knowledge_endpoint.agents_endpoint, "_get_connected_ws", _get_connected_ws)
    monkeypatch.setattr(knowledge_endpoint, "_resolve_agent_workspace", _resolve_agent_workspace)

    aid, _ws, workspace, root = asyncio.run(knowledge_endpoint._agent_context("main", _user("u1")))

    assert aid == "u1-main"
    assert workspace == foreign_workspace
    assert root.as_posix().endswith("/foreign/memory/knowledge")


def test_upload_base64_text_file_creates_markdown_sibling(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)

    created = asyncio.run(
        knowledge_endpoint.upload_file_base64(
            "main",
            KnowledgeFileBase64UploadRequest(
                path="research",
                filename="notes.txt",
                content_base64=_b64(b"hello knowledge"),
                overwrite=False,
            ),
            _user("u1"),
        )
    )

    assert created.path == "research/notes.txt"
    assert (root / "research" / "notes.txt").read_text(encoding="utf-8") == "hello knowledge"
    assert (root / "research" / "notes.md").read_text(encoding="utf-8") == "hello knowledge"


def test_upload_base64_pdf_creates_original_and_markdown(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)

    def _render(filename: str, content: bytes) -> bytes:
        assert filename == "brief.pdf"
        assert content == b"%PDF-1.7 fake"
        return b"# Converted brief\n"

    monkeypatch.setattr(knowledge_endpoint, "render_markdown_for_knowledge_upload", _render)

    created = asyncio.run(
        knowledge_endpoint.upload_file_base64(
            "main",
            KnowledgeFileBase64UploadRequest(
                path="research",
                filename="brief.pdf",
                content_base64=_b64(b"%PDF-1.7 fake"),
                overwrite=False,
            ),
            _user("u1"),
        )
    )

    assert created.path == "research/brief.pdf"
    assert (root / "research" / "brief.pdf").read_bytes() == b"%PDF-1.7 fake"
    assert (root / "research" / "brief.md").read_text(encoding="utf-8") == "# Converted brief\n"
    assert not (root / "research" / "brief.json").exists()
    assert not (root / "research" / "conversion_summary.json").exists()


def test_upload_base64_pdf_managed_pair_requires_overwrite(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    folder = root / "research"
    folder.mkdir(parents=True)
    (folder / "brief.pdf").write_bytes(b"old-pdf")
    (folder / "brief.md").write_text("old-md", encoding="utf-8")

    monkeypatch.setattr(knowledge_endpoint, "render_markdown_for_knowledge_upload", lambda _filename, _content: b"# Refreshed\n")

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            knowledge_endpoint.upload_file_base64(
                "main",
                KnowledgeFileBase64UploadRequest(
                    path="research",
                    filename="brief.pdf",
                    content_base64=_b64(b"new-pdf"),
                    overwrite=False,
                ),
                _user("u1"),
            )
        )

    assert exc_info.value.status_code == 409
    assert (folder / "brief.pdf").read_bytes() == b"old-pdf"
    assert (folder / "brief.md").read_text(encoding="utf-8") == "old-md"

    updated = asyncio.run(
        knowledge_endpoint.upload_file_base64(
            "main",
            KnowledgeFileBase64UploadRequest(
                path="research",
                filename="brief.pdf",
                content_base64=_b64(b"new-pdf"),
                overwrite=True,
            ),
            _user("u1"),
        )
    )

    assert updated.path == "research/brief.pdf"
    assert (folder / "brief.pdf").read_bytes() == b"new-pdf"
    assert (folder / "brief.md").read_text(encoding="utf-8") == "# Refreshed\n"


def test_upload_base64_pdf_sibling_only_uses_incremented_pair(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    folder = root / "research"
    folder.mkdir(parents=True)
    (folder / "brief.md").write_text("user-authored", encoding="utf-8")

    monkeypatch.setattr(knowledge_endpoint, "render_markdown_for_knowledge_upload", lambda _filename, _content: b"# Generated\n")

    created = asyncio.run(
        knowledge_endpoint.upload_file_base64(
            "main",
            KnowledgeFileBase64UploadRequest(
                path="research",
                filename="brief.pdf",
                content_base64=_b64(b"fresh-pdf"),
                overwrite=False,
            ),
            _user("u1"),
        )
    )

    assert created.path == "research/brief-1.pdf"
    assert (folder / "brief.md").read_text(encoding="utf-8") == "user-authored"
    assert (folder / "brief-1.pdf").read_bytes() == b"fresh-pdf"
    assert (folder / "brief-1.md").read_text(encoding="utf-8") == "# Generated\n"


def test_upload_base64_pdf_original_only_requires_overwrite_and_adds_markdown(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    folder = root / "research"
    folder.mkdir(parents=True)
    (folder / "brief.pdf").write_bytes(b"old-pdf")

    monkeypatch.setattr(knowledge_endpoint, "render_markdown_for_knowledge_upload", lambda _filename, _content: b"# Generated\n")

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            knowledge_endpoint.upload_file_base64(
                "main",
                KnowledgeFileBase64UploadRequest(
                    path="research",
                    filename="brief.pdf",
                    content_base64=_b64(b"new-pdf"),
                    overwrite=False,
                ),
                _user("u1"),
            )
        )

    assert exc_info.value.status_code == 409
    assert not (folder / "brief.md").exists()

    updated = asyncio.run(
        knowledge_endpoint.upload_file_base64(
            "main",
            KnowledgeFileBase64UploadRequest(
                path="research",
                filename="brief.pdf",
                content_base64=_b64(b"new-pdf"),
                overwrite=True,
            ),
            _user("u1"),
        )
    )

    assert updated.path == "research/brief.pdf"
    assert (folder / "brief.pdf").read_bytes() == b"new-pdf"
    assert (folder / "brief.md").read_text(encoding="utf-8") == "# Generated\n"


def test_replace_file_pdf_sibling_only_requires_upsert(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    folder = root / "research"
    folder.mkdir(parents=True)
    (folder / "brief.md").write_text("user-authored", encoding="utf-8")

    monkeypatch.setattr(knowledge_endpoint, "render_markdown_for_knowledge_upload", lambda _filename, _content: b"# Replaced\n")

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            knowledge_endpoint.replace_file(
                "main",
                KnowledgeFilePutRequest(
                    path="research/brief.pdf",
                    content_base64=_b64(b"new-pdf"),
                    upsert=False,
                ),
                _user("u1"),
            )
        )

    assert exc_info.value.status_code == 404

    created = asyncio.run(
        knowledge_endpoint.replace_file(
            "main",
            KnowledgeFilePutRequest(
                path="research/brief.pdf",
                content_base64=_b64(b"new-pdf"),
                upsert=True,
            ),
            _user("u1"),
        )
    )

    assert created.path == "research/brief-1.pdf"
    assert (folder / "brief.md").read_text(encoding="utf-8") == "user-authored"
    assert (folder / "brief-1.pdf").read_bytes() == b"new-pdf"
    assert (folder / "brief-1.md").read_text(encoding="utf-8") == "# Replaced\n"


def test_upload_base64_conversion_failure_does_not_write_live_files(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)

    def _raise(_filename: str, _content: bytes) -> bytes:
        raise KnowledgeConversionError("conversion failed")

    monkeypatch.setattr(knowledge_endpoint, "render_markdown_for_knowledge_upload", _raise)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            knowledge_endpoint.upload_file_base64(
                "main",
                KnowledgeFileBase64UploadRequest(
                    path="research",
                    filename="brief.pdf",
                    content_base64=_b64(b"broken"),
                    overwrite=False,
                ),
                _user("u1"),
            )
        )

    assert exc_info.value.status_code == 422
    assert not (root / "research" / "brief.pdf").exists()
    assert not (root / "research" / "brief.md").exists()



def test_upload_multipart_pdf_creates_original_and_markdown(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)

    monkeypatch.setattr(knowledge_endpoint, "render_markdown_for_knowledge_upload", lambda _filename, _content: b"# Multipart\n")

    upload = UploadFile(filename="brief.pdf", file=io.BytesIO(b"%PDF-multipart"))
    created = asyncio.run(
        knowledge_endpoint.upload_file(
            "main",
            file=upload,
            path="research",
            filename=None,
            overwrite=False,
            user=_user("u1"),
        )
    )

    assert created.path == "research/brief.pdf"
    assert (root / "research" / "brief.pdf").read_bytes() == b"%PDF-multipart"
    assert (root / "research" / "brief.md").read_text(encoding="utf-8") == "# Multipart\n"



def test_replace_file_existing_pdf_refreshes_original_and_markdown(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    folder = root / "research"
    folder.mkdir(parents=True)
    (folder / "brief.pdf").write_bytes(b"old-pdf")
    (folder / "brief.md").write_text("old-md", encoding="utf-8")

    monkeypatch.setattr(knowledge_endpoint, "render_markdown_for_knowledge_upload", lambda _filename, _content: b"# Updated\n")

    updated = asyncio.run(
        knowledge_endpoint.replace_file(
            "main",
            KnowledgeFilePutRequest(
                path="research/brief.pdf",
                content_base64=_b64(b"new-pdf"),
                upsert=False,
            ),
            _user("u1"),
        )
    )

    assert updated.path == "research/brief.pdf"
    assert (folder / "brief.pdf").read_bytes() == b"new-pdf"
    assert (folder / "brief.md").read_text(encoding="utf-8") == "# Updated\n"


def test_upload_multipart_to_managed_markdown_is_rejected(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    folder = root / 'research'
    folder.mkdir(parents=True)
    (folder / 'brief.pdf').write_bytes(b'old-pdf')
    (folder / 'brief.md').write_text('old-md', encoding='utf-8')

    def _raise(_filename: str, _content: bytes) -> bytes:
        raise AssertionError('conversion should not run for managed markdown writes')

    monkeypatch.setattr(knowledge_endpoint, 'render_markdown_for_knowledge_upload', _raise)

    upload = UploadFile(filename='brief.md', file=io.BytesIO(b'user-edit'))
    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            knowledge_endpoint.upload_file(
                'main',
                file=upload,
                path='research',
                filename=None,
                overwrite=True,
                user=_user('u1'),
            )
        )

    assert exc_info.value.status_code == 409
    assert (folder / 'brief.pdf').read_bytes() == b'old-pdf'
    assert (folder / 'brief.md').read_text(encoding='utf-8') == 'old-md'



def test_upload_multipart_to_reserved_managed_markdown_is_rejected(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    folder = root / 'research'
    folder.mkdir(parents=True)
    (folder / 'brief.pdf').write_bytes(b'old-pdf')

    def _raise(_filename: str, _content: bytes) -> bytes:
        raise AssertionError('conversion should not run for managed markdown writes')

    monkeypatch.setattr(knowledge_endpoint, 'render_markdown_for_knowledge_upload', _raise)

    upload = UploadFile(filename='brief.md', file=io.BytesIO(b'user-edit'))
    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            knowledge_endpoint.upload_file(
                'main',
                file=upload,
                path='research',
                filename=None,
                overwrite=True,
                user=_user('u1'),
            )
        )

    assert exc_info.value.status_code == 409
    assert (folder / 'brief.pdf').read_bytes() == b'old-pdf'
    assert not (folder / 'brief.md').exists()



def test_upload_base64_to_reserved_managed_markdown_is_rejected(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    folder = root / 'research'
    folder.mkdir(parents=True)
    (folder / 'brief.pdf').write_bytes(b'old-pdf')

    def _raise(_filename: str, _content: bytes) -> bytes:
        raise AssertionError('conversion should not run for managed markdown writes')

    monkeypatch.setattr(knowledge_endpoint, 'render_markdown_for_knowledge_upload', _raise)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            knowledge_endpoint.upload_file_base64(
                'main',
                KnowledgeFileBase64UploadRequest(
                    path='research',
                    filename='brief.md',
                    content_base64=_b64(b'user-edit'),
                    overwrite=True,
                ),
                _user('u1'),
            )
        )

    assert exc_info.value.status_code == 409
    assert (folder / 'brief.pdf').read_bytes() == b'old-pdf'
    assert not (folder / 'brief.md').exists()



def test_replace_file_reserved_managed_markdown_is_rejected(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    folder = root / 'research'
    folder.mkdir(parents=True)
    (folder / 'brief.pdf').write_bytes(b'old-pdf')

    def _raise(_filename: str, _content: bytes) -> bytes:
        raise AssertionError('conversion should not run for managed markdown writes')

    monkeypatch.setattr(knowledge_endpoint, 'render_markdown_for_knowledge_upload', _raise)

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(
            knowledge_endpoint.replace_file(
                'main',
                KnowledgeFilePutRequest(
                    path='research/brief.md',
                    content_base64=_b64(b'user-edit'),
                    upsert=True,
                ),
                _user('u1'),
            )
        )

    assert exc_info.value.status_code == 409
    assert (folder / 'brief.pdf').read_bytes() == b'old-pdf'
    assert not (folder / 'brief.md').exists()



def test_standalone_markdown_still_uploads_replaces_and_deletes(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)

    created = asyncio.run(
        knowledge_endpoint.upload_file_base64(
            'main',
            KnowledgeFileBase64UploadRequest(
                path='research',
                filename='note.md',
                content_base64=_b64(b'first version'),
                overwrite=False,
            ),
            _user('u1'),
        )
    )
    assert created.path == 'research/note.md'
    assert (root / 'research' / 'note.md').read_text(encoding='utf-8') == 'first version'

    updated = asyncio.run(
        knowledge_endpoint.replace_file(
            'main',
            KnowledgeFilePutRequest(
                path='research/note.md',
                content_base64=_b64(b'second version'),
                upsert=False,
            ),
            _user('u1'),
        )
    )
    assert updated.path == 'research/note.md'
    assert (root / 'research' / 'note.md').read_text(encoding='utf-8') == 'second version'

    deleted = asyncio.run(knowledge_endpoint.delete_file('main', path='research/note.md', user=_user('u1')))
    assert deleted.deleted is True
    assert not (root / 'research' / 'note.md').exists()



def test_delete_original_file_removes_managed_markdown_sibling(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    folder = root / 'research'
    folder.mkdir(parents=True)
    (folder / 'brief.pdf').write_bytes(b'old-pdf')
    (folder / 'brief.md').write_text('old-md', encoding='utf-8')

    deleted = asyncio.run(knowledge_endpoint.delete_file('main', path='research/brief.pdf', user=_user('u1')))

    assert deleted.deleted is True
    assert deleted.path == 'research/brief.pdf'
    assert not (folder / 'brief.pdf').exists()
    assert not (folder / 'brief.md').exists()



def test_delete_generated_markdown_removes_managed_original_sibling(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    folder = root / 'research'
    folder.mkdir(parents=True)
    (folder / 'brief.pdf').write_bytes(b'old-pdf')
    (folder / 'brief.md').write_text('old-md', encoding='utf-8')

    deleted = asyncio.run(knowledge_endpoint.delete_file('main', path='research/brief.md', user=_user('u1')))

    assert deleted.deleted is True
    assert deleted.path == 'research/brief.md'
    assert not (folder / 'brief.pdf').exists()
    assert not (folder / 'brief.md').exists()



def test_delete_standalone_markdown_removes_only_that_file(monkeypatch: MonkeyPatch, tmp_path: Path):
    root, _ = _patch_context(monkeypatch, tmp_path)
    folder = root / 'research'
    folder.mkdir(parents=True)
    (folder / 'note.md').write_text('standalone', encoding='utf-8')
    (folder / 'brief.pdf').write_bytes(b'old-pdf')
    (folder / 'brief.md').write_text('managed', encoding='utf-8')

    deleted = asyncio.run(knowledge_endpoint.delete_file('main', path='research/note.md', user=_user('u1')))

    assert deleted.deleted is True
    assert deleted.path == 'research/note.md'
    assert not (folder / 'note.md').exists()
    assert (folder / 'brief.pdf').read_bytes() == b'old-pdf'
    assert (folder / 'brief.md').read_text(encoding='utf-8') == 'managed'
