import sys
from pathlib import Path

import pytest
from _pytest.monkeypatch import MonkeyPatch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.knowledge_fs import atomic_delete_files, detect_mime_from_name, plan_knowledge_mutation, plan_knowledge_write


def test_plan_knowledge_mutation_standalone_markdown(tmp_path: Path):
    plan = plan_knowledge_mutation(tmp_path, 'brief.md')

    assert plan.classification == 'standalone_markdown'
    assert plan.managed_original_filename is None
    assert plan.managed_markdown_filename is None
    assert plan.delete_filenames == ('brief.md',)


def test_plan_knowledge_mutation_managed_markdown_existing(tmp_path: Path):
    (tmp_path / 'brief.pdf').write_bytes(b'pdf')
    (tmp_path / 'brief.md').write_text('md', encoding='utf-8')

    plan = plan_knowledge_mutation(tmp_path, 'brief.md')

    assert plan.classification == 'managed_markdown_existing'
    assert plan.managed_original_filename == 'brief.pdf'
    assert plan.managed_markdown_filename == 'brief.md'
    assert plan.delete_filenames == ('brief.pdf', 'brief.md')


def test_plan_knowledge_mutation_managed_markdown_reserved(tmp_path: Path):
    (tmp_path / 'brief.pdf').write_bytes(b'pdf')

    plan = plan_knowledge_mutation(tmp_path, 'brief.md')

    assert plan.classification == 'managed_markdown_reserved'
    assert plan.managed_original_filename == 'brief.pdf'
    assert plan.managed_markdown_filename == 'brief.md'
    assert plan.delete_filenames == ('brief.pdf', 'brief.md')


def test_plan_knowledge_write_new_pair(tmp_path: Path):
    plan = plan_knowledge_write(tmp_path, 'brief.pdf')

    assert plan.original_filename == 'brief.pdf'
    assert plan.markdown_filename == 'brief.md'
    assert plan.collision_rule == 'new_pair'


def test_plan_knowledge_write_managed_pair_update(tmp_path: Path):
    (tmp_path / 'brief.pdf').write_bytes(b'pdf')
    (tmp_path / 'brief.md').write_text('md', encoding='utf-8')

    plan = plan_knowledge_write(tmp_path, 'brief.pdf')

    assert plan.original_filename == 'brief.pdf'
    assert plan.markdown_filename == 'brief.md'
    assert plan.collision_rule == 'managed_pair_update'


def test_plan_knowledge_write_original_only_update(tmp_path: Path):
    (tmp_path / 'brief.pdf').write_bytes(b'pdf')

    plan = plan_knowledge_write(tmp_path, 'brief.pdf')

    assert plan.original_filename == 'brief.pdf'
    assert plan.markdown_filename == 'brief.md'
    assert plan.collision_rule == 'original_only_update'


def test_plan_knowledge_write_sibling_only_uses_first_free_increment(tmp_path: Path):
    (tmp_path / 'brief.md').write_text('user', encoding='utf-8')
    (tmp_path / 'brief-1.md').write_text('collision', encoding='utf-8')

    plan = plan_knowledge_write(tmp_path, 'brief.pdf')

    assert plan.original_filename == 'brief-2.pdf'
    assert plan.markdown_filename == 'brief-2.md'
    assert plan.collision_rule == 'incremented_pair'


@pytest.mark.parametrize(
    ('filename', 'expected'),
    [
        ('brief.pdf', 'application/pdf'),
        ('brief.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
        ('brief.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'),
        ('brief.pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'),
    ],
)
def test_detect_mime_from_name_for_docling_formats(filename: str, expected: str):
    assert detect_mime_from_name(filename) == expected


def test_atomic_delete_files_restores_targets_when_cleanup_fails(monkeypatch: MonkeyPatch, tmp_path: Path):
    first = tmp_path / 'brief.pdf'
    second = tmp_path / 'brief.md'
    first.write_bytes(b'pdf-data')
    second.write_text('md-data', encoding='utf-8')

    original_unlink = Path.unlink
    backup_unlink_calls = 0

    def _flaky_unlink(self: Path, *args, **kwargs):
        nonlocal backup_unlink_calls
        if self.suffix == '.del':
            backup_unlink_calls += 1
            if backup_unlink_calls == 2:
                raise OSError('simulated delete cleanup failure')
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, 'unlink', _flaky_unlink)

    with pytest.raises(OSError):
        atomic_delete_files([first, second])

    assert first.read_bytes() == b'pdf-data'
    assert second.read_text(encoding='utf-8') == 'md-data'
    assert not list(tmp_path.glob('*.del'))

