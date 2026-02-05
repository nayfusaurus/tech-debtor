from __future__ import annotations

from pathlib import Path
from typing import Iterator

ALWAYS_EXCLUDE = {".venv", "venv", ".git", "__pycache__", ".mypy_cache", ".ruff_cache", "node_modules", ".tox", ".eggs", "*.egg-info"}


def _is_excluded(path: Path, root: Path, exclude: list[str]) -> bool:
    rel = path.relative_to(root)
    for part in rel.parts:
        if part.startswith(".") or part in ALWAYS_EXCLUDE or part.endswith(".egg-info"):
            return True
    for pattern in exclude:
        pattern_clean = pattern.rstrip("/")
        if any(part == pattern_clean for part in rel.parts):
            return True
    return False


def scan_python_files(root: Path, exclude: list[str]) -> Iterator[Path]:
    for path in sorted(root.rglob("*.py")):
        if not path.is_file():
            continue
        if _is_excluded(path, root, exclude):
            continue
        yield path
