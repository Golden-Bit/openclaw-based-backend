import sys
from pathlib import Path

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
