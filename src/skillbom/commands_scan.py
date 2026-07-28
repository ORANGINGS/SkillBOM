from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from skillbom.manifest import build_manifest
from skillbom.models import Severity
from skillbom.parser import discover_skills
from skillbom.project import build_project_report
from skillbom.project_reporting import print_project_report, project_to_sarif
from skillbom.repository import acquire_target, is_github_repository_url
from skillbom.reporting import print_manifest, to_sarif, write_json

console = Console()


def scan_command(
    target: str,
    mode: str = "auto",
    ref: str | None = None,
    format: str = "text",
    output: Path | None = None,
    fail_on: Severity | None = None,
) -> None:
    """Scan a Skill collection or an Agent/MCP repository."""
    normalized_mode = mode.lower()
    if normalized_mode not in {"auto", "skill", "repository"}:
        raise typer.BadParameter("--mode must be auto, skill, or repository")
    try:
        with acquire_target(target, ref=ref) as acquired:
            selected = _select_mode(acquired.root, normalized_mode, target)
            if selected == "skill":
                report: Any = build_manifest(acquired.root)
                _render_skill(report, format, output)
                findings = [item for skill in report.skills for item in skill.findings]
            else:
                report = build_project_report(
                    acquired.root,
                    target=acquired.display_target,
                    source=acquired.source,
                )
                _render_project(report, format, output)
                findings = report.findings
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(1) from exc
    if fail_on is not None and any(item.severity.rank >= fail_on.rank for item in findings):
        raise typer.Exit(2)


def _select_mode(root: Path, mode: str, original_target: str) -> str:
    if mode != "auto":
        return mode
    if is_github_repository_url(original_target):
        return "repository"
    project_markers = {
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "go.mod",
        "Cargo.toml",
    }
    if (root / "SKILL.md").is_file():
        return "skill"
    if discover_skills(root) and not any((root / marker).exists() for marker in project_markers):
        return "skill"
    return "repository"


def _render_skill(report: Any, format: str, output: Path | None) -> None:
    normalized = format.lower()
    if normalized == "text":
        print_manifest(report, console)
    elif normalized == "json":
        write_json(report.to_dict(), output, console)
    elif normalized == "sarif":
        write_json(to_sarif(report), output, console)
    else:
        raise ValueError("--format must be text, json, or sarif")


def _render_project(report: Any, format: str, output: Path | None) -> None:
    normalized = format.lower()
    if normalized == "text":
        print_project_report(report, console)
    elif normalized == "json":
        write_json(report.to_dict(), output, console)
    elif normalized == "sarif":
        write_json(project_to_sarif(report), output, console)
    else:
        raise ValueError("--format must be text, json, or sarif")
