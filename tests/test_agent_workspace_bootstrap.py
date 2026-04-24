import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.agent_workspace_bootstrap import ensure_agents_md_for_agent


def test_ensure_agents_md_creates_file_when_missing(tmp_path: Path):
    workspace = tmp_path / 'workspace'

    out = ensure_agents_md_for_agent(str(workspace), user_id='u1')

    assert out == (workspace / 'AGENTS.md').resolve()
    content = out.read_text(encoding='utf-8')
    assert '## OpenClaw Custom Skills Routing' in content
    assert 'skills/share-files/SKILL.md' in content
    assert 'skills/file-reference-disambiguation/SKILL.md' in content
    assert 'skills/response-language/SKILL.md' in content
    assert 'skills/document-creation-and-manipulation/SKILL.md' in content


def test_ensure_agents_md_appends_block_without_overwriting_existing_content(tmp_path: Path):
    workspace = tmp_path / 'workspace'
    workspace.mkdir(parents=True, exist_ok=True)
    agents_md = workspace / 'AGENTS.md'
    agents_md.write_text('# Existing\n\nKeep this section.\n', encoding='utf-8')

    ensure_agents_md_for_agent(str(workspace), user_id='u1')

    content = agents_md.read_text(encoding='utf-8')
    assert '# Existing' in content
    assert 'Keep this section.' in content
    assert '<!-- OPENCLAW-BFF:SKILL-ROUTING START -->' in content
    assert 'skills/share-files/SKILL.md' in content


def test_ensure_agents_md_replaces_only_managed_block(tmp_path: Path):
    workspace = tmp_path / 'workspace'
    workspace.mkdir(parents=True, exist_ok=True)
    agents_md = workspace / 'AGENTS.md'
    agents_md.write_text(
        '# Before\n\n'
        '<!-- OPENCLAW-BFF:SKILL-ROUTING START -->\n'
        'old block\n'
        '<!-- OPENCLAW-BFF:SKILL-ROUTING END -->\n\n'
        '# After\n',
        encoding='utf-8',
    )

    ensure_agents_md_for_agent(str(workspace), user_id='u1')

    content = agents_md.read_text(encoding='utf-8')
    assert '# Before' in content
    assert '# After' in content
    assert 'old block' not in content
    assert content.count('<!-- OPENCLAW-BFF:SKILL-ROUTING START -->') == 1
    assert 'skills/document-creation-and-manipulation/SKILL.md' in content


def test_ensure_agents_md_is_idempotent_when_already_current(tmp_path: Path):
    workspace = tmp_path / 'workspace'

    first = ensure_agents_md_for_agent(str(workspace), user_id='u1')
    first_content = first.read_text(encoding='utf-8')

    second = ensure_agents_md_for_agent(str(workspace), user_id='u1')
    second_content = second.read_text(encoding='utf-8')

    assert second == first
    assert second_content == first_content
