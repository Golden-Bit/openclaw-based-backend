import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core import knowledge_conversion as conversion
from app.core.knowledge_conversion import KnowledgeConversionDependencyError, KnowledgeConversionError



def test_render_markdown_for_text_passthrough():
    data = b'hello knowledge'

    assert conversion.render_markdown_for_knowledge_upload('notes.txt', data) == data
    assert conversion.render_markdown_for_knowledge_upload('payload.json', b'{"ok":true}') == b'{"ok":true}'



def test_render_markdown_for_text_rejects_non_utf8():
    with pytest.raises(KnowledgeConversionError):
        conversion.render_markdown_for_knowledge_upload('notes.txt', b'\xff\xfe')



def test_load_docling_converter_class_from_file_path_fallback(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(conversion.importlib, 'import_module', lambda _name: (_ for _ in ()).throw(ModuleNotFoundError('forced')))

    converter_cls = conversion._load_docling_converter_class()

    assert converter_cls.__name__ == 'DoclingMarkdownConverter'



def test_render_markdown_for_docling_missing_dependency(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(conversion.importlib, 'import_module', lambda _name: (_ for _ in ()).throw(ModuleNotFoundError('forced')))
    monkeypatch.setattr(conversion, '_converter_module_path', lambda: tmp_path / 'missing_docling_converter.py')

    with pytest.raises(KnowledgeConversionDependencyError):
        conversion.render_markdown_for_knowledge_upload('brief.pdf', b'%PDF-1.7 fake')


def test_render_markdown_for_docling_reuses_default_converter_and_keeps_output_dir_request_scoped(
    monkeypatch: pytest.MonkeyPatch,
):
    class FakeConverter:
        init_calls = 0

        def __init__(self):
            type(self).init_calls += 1
            self.output_dirs: list[Path] = []

        def convert_file(self, source: str | Path, output_dir: str | Path):
            output_path = Path(output_dir)
            self.output_dirs.append(output_path)
            markdown_path = output_path / f'{Path(source).stem}.md'
            markdown_path.parent.mkdir(parents=True, exist_ok=True)
            markdown_path.write_text(f'converted:{Path(source).name}', encoding='utf-8')
            return SimpleNamespace(output_markdown=markdown_path)

    monkeypatch.setattr(conversion, '_DEFAULT_DOCLING_CONVERTER', None)
    monkeypatch.setattr(conversion, '_load_docling_converter_class', lambda: FakeConverter)

    first = conversion.render_markdown_for_knowledge_upload('brief.pdf', b'%PDF-1.7 fake')
    second = conversion.render_markdown_for_knowledge_upload('deck.pptx', b'fake pptx bytes')

    cached_converter = conversion._DEFAULT_DOCLING_CONVERTER
    assert FakeConverter.init_calls == 1
    assert cached_converter is not None
    assert first == b'converted:brief.pdf'
    assert second == b'converted:deck.pptx'
    assert len(cached_converter.output_dirs) == 2
    assert cached_converter.output_dirs[0] != cached_converter.output_dirs[1]
    assert all(path.name == 'out' for path in cached_converter.output_dirs)
