from __future__ import annotations

from pathlib import Path

from security_ai_agent.discovery import collect_files, load_codebase


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "vuln_repo"


def test_collect_files_excludes_generated_and_binary_paths() -> None:
    files = collect_files(str(FIXTURE_ROOT))
    rel = sorted(path.relative_to(FIXTURE_ROOT).as_posix() for path in files)

    assert "app.py" in rel
    assert "auth.js" in rel
    assert "logging.py" in rel
    assert "docs/notes.md" in rel

    assert "node_modules/ignored.js" not in rel
    assert "dist/bundle.min.js" not in rel
    assert "binary.bin" not in rel


def test_collect_files_with_include_glob() -> None:
    files = collect_files(str(FIXTURE_ROOT), include_globs=["*.py"])
    rel = sorted(path.relative_to(FIXTURE_ROOT).as_posix() for path in files)
    assert rel == ["app.py", "logging.py"]


def test_load_codebase_returns_relative_paths() -> None:
    files = collect_files(str(FIXTURE_ROOT), include_globs=["app.py"])
    loaded = load_codebase(files, FIXTURE_ROOT)
    assert "app.py" in loaded
    assert "DB_PASSWORD" in loaded["app.py"]
