from __future__ import annotations

import argparse
from pathlib import Path

from docling_converter import DoclingMarkdownConverter

DEFAULT_FILES = [
    "complex_program_brief.docx",
    "complex_operations_dashboard.xlsx",
    "complex_steering_committee_update.pptx",
    "complex_supplier_resilience_assessment.pdf",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Process the sample assets with the DoclingMarkdownConverter class.")
    parser.add_argument("--input-dir", default=str(Path(__file__).resolve().parents[1] / "inputs"), help="Directory containing the sample files")
    parser.add_argument("--output-dir", default=str(Path(__file__).resolve().parents[1] / "outputs"), help="Directory where Markdown files will be written")
    parser.add_argument("--ocr", action="store_true", help="Enable OCR for PDFs")
    parser.add_argument("--force-full-page-ocr", action="store_true", help="If supported, run OCR on all PDF pages")
    parser.add_argument("--continue-on-error", action="store_true", help="Continue processing after one file fails")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    files = [input_dir / name for name in DEFAULT_FILES]
    converter = DoclingMarkdownConverter(
        do_ocr=args.ocr,
        force_full_page_ocr=args.force_full_page_ocr,
        abort_on_error=not args.continue_on_error,
    )
    reports = converter.convert_many(files, output_dir=output_dir)
    print("\nConversion results")
    print("-" * 72)
    for report in reports:
        print(f"{report.status.upper():<8} {report.source.name}")
        print(f"         output: {report.output_markdown}")
        if report.notes:
            for note in report.notes:
                print(f"         note: {note}")


if __name__ == "__main__":
    main()
