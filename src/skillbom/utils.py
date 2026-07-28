from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import urlparse

TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
}

IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
URL_RE = re.compile(r"https?://[^\s)\]>'\"]+")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_text(path: Path) -> str | None:
    if path.suffix.lower() not in TEXT_EXTENSIONS and path.name != "SKILL.md":
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_symlink():
            continue
        if path.is_file():
            files.append(path)
    return sorted(files)


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def clean_snippet(line: str, limit: int = 180) -> str:
    value = " ".join(line.strip().split())
    if len(value) > limit:
        return value[: limit - 1] + "…"
    return value


def extract_urls(text: str) -> list[str]:
    return URL_RE.findall(text)


def domain_from_url(url: str) -> str | None:
    try:
        return urlparse(url).hostname
    except ValueError:
        return None
