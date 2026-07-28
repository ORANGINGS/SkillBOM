from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from skillbom.diffing import compare_manifests
from skillbom.models import Drift, Severity
from skillbom.project import build_project_report, compare_project_reports
from skillbom.reporting import print_drifts, write_json
from skillbom.repository import acquire_target, is_github_repository_url

console = Console()


def diff_command(
    old: Path,
    new: Path,
    json_output: Path | None = None,
    fail_on: Severity | None = Severity.HIGH,
) -> None:
    """Compare Skill lockfiles or repository scan reports."""
    try:
        old_data = json.loads(old.read_text(encoding="utf-8"))
        new_data = json.loads(new.read_text(encoding="utf-8"))
        if "project_types" in old_data or "project_types" in new_data:
            drifts = compare_project_reports(old_data, new_data)
        else:
            drifts = compare_manifests(old_data, new_data)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(1) from exc
    _render_drifts(drifts, json_output, fail_on)


def repo_diff_command(
    repository: str,
    base_ref: str,
    head_ref: str,
    json_output: Path | None = None,
    fail_on: Severity | None = Severity.HIGH,
) -> None:
    """Compare capabilities and exposed MCP tools between two Git refs."""
    if not is_github_repository_url(repository):
        raise typer.BadParameter("repo-diff requires a public GitHub repository URL")
    try:
        with acquire_target(repository, ref=base_ref) as old_target:
            old_report = build_project_report(
                old_target.root,
                target=repository,
                source=old_target.source,
                include_timestamp=False,
            )
        with acquire_target(repository, ref=head_ref) as new_target:
            new_report = build_project_report(
                new_target.root,
                target=repository,
                source=new_target.source,
                include_timestamp=False,
            )
        drifts = compare_project_reports(old_report.to_dict(), new_report.to_dict())
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(1) from exc
    _render_drifts(drifts, json_output, fail_on)


def _render_drifts(
    drifts: list[Drift], json_output: Path | None, fail_on: Severity | None
) -> None:
    print_drifts(drifts, console)
    if json_output:
        write_json(
            [
                {
                    "kind": item.kind,
                    "severity": item.severity.value,
                    "skill": item.skill,
                    "item": item.item,
                    "message": item.message,
                }
                for item in drifts
            ],
            json_output,
            console,
        )
    if fail_on is not None and any(item.severity.rank >= fail_on.rank for item in drifts):
        raise typer.Exit(2)
