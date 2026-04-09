import asyncio
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException
from _pytest.monkeypatch import MonkeyPatch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.api import shared_files as shared_files_api
from app.core.config import settings
from app.core.shared_files import normalize_shared_relative_path, resolve_shared_file_path


def test_shared_relative_normalization():
    assert normalize_shared_relative_path("a/b/c.txt") == "a/b/c.txt"
    assert normalize_shared_relative_path("a\\b\\c.txt") == "a/b/c.txt"


def test_shared_path_resolve_and_download(monkeypatch: MonkeyPatch, tmp_path: Path):
    shared_root = (tmp_path / "shared").resolve()
    shared_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "shared_files_root", shared_root.as_posix())

    f = shared_root / "user" / "r" / "report.md"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("# report", encoding="utf-8")

    target = resolve_shared_file_path("user/r/report.md")
    assert target == f

    response = asyncio.run(shared_files_api.get_shared_file("user/r/report.md", download=True))
    assert response.filename == "report.md"
    assert str(response.path).endswith(str(f))


def test_shared_path_traversal_blocked(monkeypatch: MonkeyPatch, tmp_path: Path):
    shared_root = (tmp_path / "shared").resolve()
    shared_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "shared_files_root", shared_root.as_posix())

    with pytest.raises(HTTPException) as exc_info:
        _ = asyncio.run(shared_files_api.get_shared_file("../secret.txt", download=False))

    assert exc_info.value.status_code == 404
