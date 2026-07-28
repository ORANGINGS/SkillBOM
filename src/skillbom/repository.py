from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

GITHUB_HOST = "github.com"
REPOSITORY_PATH_RE = re.compile(r"\A/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?\Z")
DEFAULT_CLONE_TIMEOUT_SECONDS = 120
DEFAULT_MAX_FILES = 20_000
DEFAULT_MAX_BYTES = 250 * 1024 * 1024
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}


@dataclass(slots=True, frozen=True)
class AcquiredTarget:
    root: Path
    display_target: str
    source: dict[str, str]
    temporary: bool = False


def normalize_github_repository_url(value: str) -> tuple[str, str]:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or parsed.hostname != GITHUB_HOST:
        raise ValueError("Only public https://github.com/owner/repository URLs are supported.")
    if parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
        raise ValueError("GitHub URL must not include credentials, a port, query parameters, or a fragment.")
    match = REPOSITORY_PATH_RE.fullmatch(parsed.path)
    if not match:
        raise ValueError("GitHub URL must identify exactly one owner/repository pair.")
    owner = match.group("owner")
    repository = match.group("repo")
    if owner in {".", ".."} or repository in {".", ".."}:
        raise ValueError("Invalid GitHub owner or repository name.")
    slug = f"{owner}/{repository}"
    return f"https://github.com/{slug}.git", slug


def is_github_repository_url(value: str) -> bool:
    try:
        normalize_github_repository_url(value)
    except ValueError:
        return False
    return True


@contextmanager
def acquire_target(
    target: str,
    *,
    ref: str | None = None,
    timeout_seconds: int = DEFAULT_CLONE_TIMEOUT_SECONDS,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> Iterator[AcquiredTarget]:
    local = Path(target).expanduser()
    if local.exists():
        root = local.parent if local.is_file() and local.name == "SKILL.md" else local
        if not root.is_dir():
            raise ValueError(f"Target is not a directory or SKILL.md: {target}")
        _enforce_repository_limits(root, max_files=max_files, max_bytes=max_bytes)
        yield AcquiredTarget(root.resolve(), target, {"kind": "local"})
        return

    clone_url, slug = normalize_github_repository_url(target)
    temporary = tempfile.TemporaryDirectory(prefix="skillbom-repo-")
    root = Path(temporary.name) / "repository"
    command = [
        "git",
        "clone",
        "--depth",
        "1",
        "--no-tags",
        "--single-branch",
        "--config",
        "core.hooksPath=/dev/null",
    ]
    if ref:
        command.extend(["--branch", ref])
    command.extend([clone_url, str(root)])
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "never",
            "GIT_ASKPASS": "",
        }
    )
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=environment,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip() or "git clone failed"
            raise ValueError(f"Could not clone public repository: {detail}")
        _enforce_repository_limits(root, max_files=max_files, max_bytes=max_bytes)
        source = {"kind": "github", "repository": slug, "url": clone_url.removesuffix(".git")}
        if ref:
            source["ref"] = ref
        yield AcquiredTarget(root, target, source, temporary=True)
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"Repository clone exceeded {timeout_seconds} seconds.") from exc
    finally:
        temporary.cleanup()


def _enforce_repository_limits(root: Path, *, max_files: int, max_bytes: int) -> None:
    file_count = 0
    total_bytes = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise ValueError(f"Could not inspect repository path {directory}: {exc}") from exc
        for entry in entries:
            if entry.name in IGNORED_DIRS and entry.is_dir(follow_symlinks=False):
                continue
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                stack.append(Path(entry.path))
                continue
            if not entry.is_file(follow_symlinks=False):
                continue
            file_count += 1
            try:
                total_bytes += entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
            if file_count > max_files:
                raise ValueError(f"Repository exceeds the {max_files} file scan limit.")
            if total_bytes > max_bytes:
                raise ValueError(f"Repository exceeds the {max_bytes} byte scan limit.")


def git_available() -> bool:
    return shutil.which("git") is not None
