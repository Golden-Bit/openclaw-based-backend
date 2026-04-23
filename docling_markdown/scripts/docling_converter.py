from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


SUPPORTED_SUFFIXES = {".pdf", ".docx", ".xlsx", ".pptx"}


@dataclass
class ConversionReport:
    source: Path
    output_markdown: Path
    status: str
    notes: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class DoclingMarkdownConverter:
    do_ocr: bool = False
    force_full_page_ocr: bool = False
    abort_on_error: bool = True

    def __post_init__(self) -> None:
        self._converter = self._build_converter()

    def _build_converter(self):
        try:
            from docling.document_converter import DocumentConverter
        except ImportError as exc:
            raise RuntimeError(
                "Docling is not installed. Install it with: "
                "pip install docling --extra-index-url https://download.pytorch.org/whl/cpu"
            ) from exc

        if not self.do_ocr:
            return DocumentConverter()

        notes = []
        try:
            from docling.document_converter import InputFormat, PdfFormatOption
            from docling.datamodel.pipeline_options import PdfPipelineOptions

            pipeline_options = PdfPipelineOptions()
            pipeline_options.do_ocr = True
            if hasattr(pipeline_options, "force_full_page_ocr"):
                pipeline_options.force_full_page_ocr = self.force_full_page_ocr
            format_options = {
                InputFormat.PDF: PdfFormatOption(pipeline_options=pipeline_options)
            }
            return DocumentConverter(format_options=format_options)
        except Exception as exc:
            notes.append(f"Falling back to default DocumentConverter because OCR options could not be configured: {exc}")
            self._converter_notes = notes
            return DocumentConverter()

    def supports(self, path: str | Path) -> bool:
        return Path(path).suffix.lower() in SUPPORTED_SUFFIXES

    def _resolve_output_dir(self, output_dir: str | Path) -> Path:
        resolved = Path(output_dir)
        resolved.mkdir(parents=True, exist_ok=True)
        return resolved

    def _target_markdown_path(self, source: Path, output_dir: Path) -> Path:
        return output_dir / f"{source.stem}.md"

    def convert_file(self, source: str | Path, output_dir: str | Path) -> ConversionReport:
        src = Path(source)
        if not src.exists():
            raise FileNotFoundError(f"Input file not found: {src}")
        if not self.supports(src):
            raise ValueError(f"Unsupported input type: {src.suffix}")

        resolved_output_dir = self._resolve_output_dir(output_dir)
        target = self._target_markdown_path(src, resolved_output_dir)
        result = self._converter.convert(str(src))
        document = result.document
        markdown = document.export_to_markdown()
        target.write_text(markdown, encoding="utf-8")

        metadata = {
            "source_name": src.name,
            "source_suffix": src.suffix.lower(),
            "output_name": target.name,
            "ocr_requested": self.do_ocr,
            "force_full_page_ocr": self.force_full_page_ocr,
        }
        if hasattr(result, "input"):
            metadata["docling_input"] = str(result.input)
        if hasattr(self, "_converter_notes"):
            metadata["converter_notes"] = self._converter_notes
        meta_path = target.with_suffix(".json")
        meta_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
        return ConversionReport(source=src, output_markdown=target, status="ok", metadata=metadata)

    def convert_many(self, sources: Iterable[str | Path], output_dir: str | Path) -> list[ConversionReport]:
        resolved_output_dir = self._resolve_output_dir(output_dir)
        reports: list[ConversionReport] = []
        for source in sources:
            try:
                reports.append(self.convert_file(source, resolved_output_dir))
            except Exception as exc:
                src = Path(source)
                report = ConversionReport(
                    source=src,
                    output_markdown=self._target_markdown_path(src, resolved_output_dir),
                    status="error",
                    notes=[str(exc)],
                )
                reports.append(report)
                if self.abort_on_error:
                    raise
        summary = [
            {
                "source": str(r.source),
                "output_markdown": str(r.output_markdown),
                "status": r.status,
                "notes": r.notes,
            }
            for r in reports
        ]
        (resolved_output_dir / "conversion_summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return reports


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert supported office documents to Markdown with Docling.")
    parser.add_argument("inputs", nargs="+", help="Files to convert")
    parser.add_argument("--output-dir", required=True, help="Destination folder for .md outputs")
    parser.add_argument("--ocr", action="store_true", help="Enable OCR for PDFs")
    parser.add_argument("--force-full-page-ocr", action="store_true", help="If supported by the installed Docling version, OCR every PDF page")
    parser.add_argument("--continue-on-error", action="store_true", help="Continue processing after an error")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    converter = DoclingMarkdownConverter(
        do_ocr=args.ocr,
        force_full_page_ocr=args.force_full_page_ocr,
        abort_on_error=not args.continue_on_error,
    )
    reports = converter.convert_many(args.inputs, output_dir=Path(args.output_dir))
    for report in reports:
        print(f"[{report.status}] {report.source.name} -> {report.output_markdown}")
        for note in report.notes:
            print(f"  note: {note}")


if __name__ == "__main__":
    main()
