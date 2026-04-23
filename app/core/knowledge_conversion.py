from __future__ import annotations

import importlib
import importlib.util
import sys
import tempfile
from pathlib import Path

from app.core.knowledge_fs import DOCLING_KNOWLEDGE_EXTENSIONS, knowledge_file_extension


_DEFAULT_DOCLING_CONVERTER = None


class KnowledgeConversionError(RuntimeError):
    pass


class KnowledgeConversionDependencyError(KnowledgeConversionError):
    pass


def _converter_module_path() -> Path:
    return Path(__file__).resolve().parents[2] / "docling_markdown" / "scripts" / "docling_converter.py"


def _load_docling_converter_class():
    module_name = "docling_markdown.scripts.docling_converter"

    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError:
        module_path = _converter_module_path()
        if not module_path.exists():
            raise KnowledgeConversionDependencyError(f"Docling converter module not found at {module_path}") from None

        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            raise KnowledgeConversionDependencyError(f"Unable to load Docling converter module from {module_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

    converter_cls = getattr(module, "DoclingMarkdownConverter", None)
    if converter_cls is None:
        raise KnowledgeConversionDependencyError("Docling converter class is unavailable")
    return converter_cls


def _get_default_docling_converter():
    global _DEFAULT_DOCLING_CONVERTER

    if _DEFAULT_DOCLING_CONVERTER is None:
        converter_cls = _load_docling_converter_class()
        _DEFAULT_DOCLING_CONVERTER = converter_cls()

    return _DEFAULT_DOCLING_CONVERTER


def _convert_with_docling(filename: str, content: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmp_dir_name:
        tmp_dir = Path(tmp_dir_name)
        source_path = tmp_dir / filename
        output_dir = tmp_dir / "out"
        source_path.write_bytes(content)

        try:
            converter = _get_default_docling_converter()
            report = converter.convert_file(source_path, output_dir=output_dir)
        except RuntimeError as exc:
            raise KnowledgeConversionDependencyError(str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise KnowledgeConversionError(f"Docling conversion failed for {filename}: {exc}") from exc

        markdown_path = Path(report.output_markdown)
        if not markdown_path.exists():
            raise KnowledgeConversionError(f"Docling did not produce markdown for {filename}")
        return markdown_path.read_bytes()


def render_markdown_for_knowledge_upload(filename: str, content: bytes) -> bytes:
    ext = knowledge_file_extension(filename)
    if ext == ".md":
        return content
    if ext in DOCLING_KNOWLEDGE_EXTENSIONS:
        return _convert_with_docling(filename, content)

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KnowledgeConversionError(f"Unable to decode {filename} as UTF-8 text for markdown generation") from exc
    return text.encode("utf-8")
