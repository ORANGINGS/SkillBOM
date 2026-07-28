from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from skillbom.repository import acquire_target, normalize_github_repository_url


def test_normalize_public_github_url() -> None:
    clone_url, slug = normalize_github_repository_url("https://github.com/ORANGINGS/SkillBOM.git")
    assert clone_url == "https://github.com/ORANGINGS/SkillBOM.git"
    assert slug == "ORANGINGS/SkillBOM"


@pytest.mark.parametrize(
    "value",
    [
        "http://github.com/owner/repo",
        "https://gitlab.com/owner/repo",
        "https://token@github.com/owner/repo",
        "https://github.com/owner/repo?x=1",
        "https://github.com/owner/repo/issues",
    ],
)
def test_rejects_unsafe_or_non_repository_urls(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_github_repository_url(value)


def test_clone_uses_noninteractive_shallow_command(tmp_path: Path) -> None:
    def fake_run(command, **kwargs):  # type: ignore[no-untyped-def]
        destination = Path(command[-1])
        destination.mkdir(parents=True)
        (destination / "README.md").write_text("demo", encoding="utf-8")
        return Mock(returncode=0, stdout="", stderr="")

    with patch("skillbom.repository.tempfile.TemporaryDirectory") as temporary, patch(
        "skillbom.repository.subprocess.run", side_effect=fake_run
    ) as run:
        temporary.return_value.name = str(tmp_path / "temp")
        temporary.return_value.cleanup = Mock()
        with acquire_target("https://github.com/owner/repo", ref="v1.0.0") as acquired:
            assert acquired.source["repository"] == "owner/repo"
            assert acquired.root.name == "repository"
    command = run.call_args.args[0]
    assert command[:4] == ["git", "clone", "--depth", "1"]
    assert "--no-tags" in command
    assert command[command.index("--branch") + 1] == "v1.0.0"
    assert run.call_args.kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
