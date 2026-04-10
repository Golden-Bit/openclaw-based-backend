from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_EXAMPLE = ROOT / ".env.example"
ENV_REFERENCE = ROOT / "docs" / "ENV_REFERENCE.md"
README = ROOT / "README.md"
RUNBOOK = ROOT / "docs" / "RUNBOOK.md"


def _env_names_from_example() -> set[str]:
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    active = re.findall(r"^([A-Z][A-Z0-9_]*)=", text, flags=re.MULTILINE)
    commented = re.findall(r"^#\s*([A-Z][A-Z0-9_]*)=", text, flags=re.MULTILINE)
    return set(active) | set(commented)


def _doc_env_names() -> set[str]:
    text = ENV_REFERENCE.read_text(encoding="utf-8")
    return set(re.findall(r"`([A-Z][A-Z0-9_]*)`", text))


def _table_row_exists(var_name: str) -> bool:
    text = ENV_REFERENCE.read_text(encoding="utf-8")
    pattern = rf"^\|\s*`{re.escape(var_name)}`\s*\|"
    return re.search(pattern, text, flags=re.MULTILINE) is not None


def _runtime_only_env_names() -> set[str]:
    config_text = (ROOT / "app" / "core" / "config.py").read_text(encoding="utf-8")
    ws_text = (ROOT / "app" / "core" / "openclaw_ws.py").read_text(encoding="utf-8")

    config_aliases = set(re.findall(r'alias="([A-Z][A-Z0-9_]*)"', config_text))
    ws_envs = set(re.findall(r'os\.getenv\("([A-Z][A-Z0-9_]*)"', ws_text))
    ws_envs |= set(re.findall(r'_env\("([A-Z][A-Z0-9_]*)"', ws_text))
    return config_aliases | ws_envs


def test_env_reference_covers_every_variable_in_env_example() -> None:
    expected = _env_names_from_example()
    documented = _doc_env_names()
    missing = sorted(expected - documented)
    assert not missing, f"Missing env vars in docs/ENV_REFERENCE.md: {missing}"


def test_every_env_example_variable_has_a_structured_table_row() -> None:
    expected = sorted(_env_names_from_example())
    missing = [name for name in expected if not _table_row_exists(name)]
    assert not missing, f"Env vars missing dedicated table rows in docs/ENV_REFERENCE.md: {missing}"


def test_runtime_only_environment_variables_are_documented_too() -> None:
    runtime_names = _runtime_only_env_names()
    documented = _doc_env_names()
    missing = sorted(runtime_names - documented)
    assert not missing, f"Runtime env vars missing in docs/ENV_REFERENCE.md: {missing}"


def test_readme_links_to_env_reference() -> None:
    text = README.read_text(encoding="utf-8")
    assert "docs/ENV_REFERENCE.md" in text


def test_runbook_links_to_env_reference() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")
    assert "ENV_REFERENCE.md" in text
