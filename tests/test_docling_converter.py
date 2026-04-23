import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from docling_markdown.scripts.docling_converter import DoclingMarkdownConverter


class _FakeDocument:
    def __init__(self, markdown: str):
        self._markdown = markdown

    def export_to_markdown(self) -> str:
        return self._markdown


class _FakeBackendConverter:
    def convert(self, source: str):
        src = Path(source)
        return SimpleNamespace(document=_FakeDocument(f'# converted\n\n{src.name}'), input=src)


def test_convert_file_uses_per_call_output_dir_and_writes_sidecar_json(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(DoclingMarkdownConverter, '_build_converter', lambda self: _FakeBackendConverter())

    source = tmp_path / 'brief.docx'
    source.write_text('fake docx payload', encoding='utf-8')
    output_a = tmp_path / 'out-a'
    output_b = tmp_path / 'out-b'
    converter = DoclingMarkdownConverter(do_ocr=True, force_full_page_ocr=True)

    first_report = converter.convert_file(source, output_dir=output_a)
    second_report = converter.convert_file(source, output_dir=output_b)

    assert not hasattr(converter, 'output_dir')
    assert first_report.output_markdown == output_a / 'brief.md'
    assert second_report.output_markdown == output_b / 'brief.md'
    assert first_report.output_markdown.read_text(encoding='utf-8') == '# converted\n\nbrief.docx'
    assert second_report.output_markdown.read_text(encoding='utf-8') == '# converted\n\nbrief.docx'

    first_metadata = json.loads((output_a / 'brief.json').read_text(encoding='utf-8'))
    second_metadata = json.loads((output_b / 'brief.json').read_text(encoding='utf-8'))
    assert first_metadata['ocr_requested'] is True
    assert second_metadata['force_full_page_ocr'] is True


def test_convert_many_writes_summary_into_requested_output_dir(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(DoclingMarkdownConverter, '_build_converter', lambda self: _FakeBackendConverter())

    source_a = tmp_path / 'brief.docx'
    source_b = tmp_path / 'deck.pptx'
    source_a.write_text('fake docx payload', encoding='utf-8')
    source_b.write_text('fake pptx payload', encoding='utf-8')
    output_dir = tmp_path / 'demo-output'
    converter = DoclingMarkdownConverter()

    reports = converter.convert_many([source_a, source_b], output_dir=output_dir)

    summary = json.loads((output_dir / 'conversion_summary.json').read_text(encoding='utf-8'))
    assert [report.output_markdown for report in reports] == [output_dir / 'brief.md', output_dir / 'deck.md']
    assert [entry['output_markdown'] for entry in summary] == [
        str(output_dir / 'brief.md'),
        str(output_dir / 'deck.md'),
    ]
