from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".cs",
    ".swift",
    ".kt",
    ".m",
    ".mm",
    ".scala",
    ".sh",
    ".bash",
    ".zsh",
    ".yaml",
    ".yml",
    ".toml",
    ".json",
    ".json5",
    ".md",
    ".txt",
    ".env",
    ".conf",
    ".ini",
    ".cfg",
    ".xml",
    ".sql",
    ".dockerfile",
    ".tf",
    ".hcl",
    ".html",
    ".css",
    ".scss",
    ".sass",
    ".vue",
    ".svelte",
    ".ipynb",
}

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    "target",
    ".next",
    ".nuxt",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".security-agent",
}

DEFAULT_EXCLUDE_GLOBS = {
    "*.min.js",
    "*.map",
    "*.lock",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.pdf",
    "*.zip",
    "*.gz",
    "*.tar",
    "*.jar",
    "*.war",
    "*.bin",
    "*.exe",
    "*.dll",
    "*.so",
    "*.dylib",
}


def is_probably_text(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    if path.name.lower() == "dockerfile":
        return True
    try:
        chunk = path.read_bytes()[:4096]
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    if not chunk:
        return True
    printable = sum(1 for b in chunk if 9 <= b <= 13 or 32 <= b <= 126)
    ratio = printable / len(chunk)
    return ratio > 0.85


def _matches_any_glob(path: Path, globs: list[str] | None) -> bool:
    if not globs:
        return False
    candidate = path.as_posix()
    return any(fnmatch(candidate, pattern) or fnmatch(path.name, pattern) for pattern in globs)


def collect_files(
    target_path: str,
    include_globs: list[str] | None = None,
    exclude_globs: list[str] | None = None,
    max_files: int | None = None,
) -> list[Path]:
    root = Path(target_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    if root.is_file():
        return [root] if is_probably_text(root) else []

    found: list[Path] = []
    effective_excludes = list(DEFAULT_EXCLUDE_GLOBS)
    if exclude_globs:
        effective_excludes.extend(exclude_globs)

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue

        relative = path.relative_to(root)
        if any(part in DEFAULT_EXCLUDE_DIRS for part in relative.parts):
            continue

        if _matches_any_glob(relative, effective_excludes):
            continue

        if include_globs and not _matches_any_glob(relative, include_globs):
            continue

        if not is_probably_text(path):
            continue

        found.append(path)
        if max_files is not None and len(found) >= max_files:
            break

    return found


def read_text_file(path: Path) -> str:
    # Fallback decoding keeps the scanner resilient across mixed-encoding repos.
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    return path.read_text(encoding="utf-8", errors="replace")


def load_codebase(
    paths: list[Path],
    root: Path,
) -> dict[str, str]:
    loaded: dict[str, str] = {}
    for path in paths:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
        loaded[relative] = read_text_file(path)
    return loaded
