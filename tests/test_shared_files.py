import sys
from pathlib import Path

from _pytest.monkeypatch import MonkeyPatch
from fastapi import FastAPI
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.api import shared_files as shared_files_api
from app.core.config import settings
from app.core.shared_files import normalize_shared_relative_path, resolve_shared_file_path


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(shared_files_api.router)
    return TestClient(app)


def test_shared_relative_normalization():
    assert normalize_shared_relative_path("a/b/c.txt") == "a/b/c.txt"
    assert normalize_shared_relative_path("a\\b\\c.txt") == "a/b/c.txt"


def test_shared_path_resolve_and_default_download(monkeypatch: MonkeyPatch, tmp_path: Path):
    shared_root = (tmp_path / "shared").resolve()
    shared_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "shared_files_root", shared_root.as_posix())

    f = shared_root / "user" / "r" / "report.md"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("# report", encoding="utf-8")

    target = resolve_shared_file_path("user/r/report.md")
    assert target == f

    with _client() as client:
        response = client.get("/shared/files/user/r/report.md")

    assert response.status_code == 200
    assert response.headers["content-disposition"] == 'attachment; filename="report.md"'


def test_shared_path_supports_explicit_inline_override(monkeypatch: MonkeyPatch, tmp_path: Path):
    shared_root = (tmp_path / "shared").resolve()
    shared_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "shared_files_root", shared_root.as_posix())

    f = shared_root / "user" / "r" / "report.md"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("# report", encoding="utf-8")

    with _client() as client:
        response = client.get("/shared/files/user/r/report.md?download=false")
        response_inline = client.get("/shared/files/user/r/report.md?inline=true")

    assert response.status_code == 200
    assert "content-disposition" not in response.headers
    assert response_inline.status_code == 200
    assert "content-disposition" not in response_inline.headers


def test_shared_path_inline_override_wins_over_download_true(monkeypatch: MonkeyPatch, tmp_path: Path):
    shared_root = (tmp_path / "shared").resolve()
    shared_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "shared_files_root", shared_root.as_posix())

    f = shared_root / "user" / "r" / "report.md"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("# report", encoding="utf-8")

    with _client() as client:
        response = client.get("/shared/files/user/r/report.md?download=true&inline=true")

    assert response.status_code == 200
    assert "content-disposition" not in response.headers


def test_shared_path_traversal_blocked(monkeypatch: MonkeyPatch, tmp_path: Path):
    shared_root = (tmp_path / "shared").resolve()
    shared_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "shared_files_root", shared_root.as_posix())

    with _client() as client:
        response = client.get("/shared/files/../secret.txt")

    assert response.status_code == 404
