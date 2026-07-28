from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from skillbom import __version__
from skillbom.diffing import compare_manifests
from skillbom.manifest import build_manifest, read_manifest, write_manifest
from skillbom.models import Severity
from skillbom.policy import evaluate_policy, read_policy, write_default_policy
from skillbom.reporting import (
    policy_violations_to_sarif,
    print_drifts,
    print_manifest,
    print_policy_violations,
    to_sarif,
    write_json,
)

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Generate Agent Skill bills of materials and detect capability drift.",
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"skillbom {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Inspect Agent Skills without executing them."""


@app.command()
def scan(
    target: Annotated[Path, typer.Argument(help="Skill directory, SKILL.md, or skills root.")],
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: text, json, or sarif."),
    ] = "text",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write JSON/SARIF output to a file."),
    ] = None,
    fail_on: Annotated[
        Severity | None,
        typer.Option(help="Exit 2 when a finding at or above this severity is present."),
    ] = None,
) -> None:
    """Scan one or more skills and infer capabilities, dependencies, and risks."""
    try:
        manifest = build_manifest(target)
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    normalized = format.lower()
    if normalized == "text":
        print_manifest(manifest, console)
    elif normalized == "json":
        write_json(manifest.to_dict(), output, console)
    elif normalized == "sarif":
        write_json(to_sarif(manifest), output, console)
    else:
        console.print("[bold red]error:[/bold red] --format must be text, json, or sarif")
        raise typer.Exit(1)

    if fail_on is not None and any(
        finding.severity.rank >= fail_on.rank
        for skill in manifest.skills
        for finding in skill.findings
    ):
        raise typer.Exit(2)


@app.command("lock")
def lock_manifest(
    target: Annotated[Path, typer.Argument(help="Skill directory or skills root.")],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Lockfile path."),
    ] = Path("skillbom.lock.json"),
) -> None:
    """Create a deterministic review baseline for skill capabilities and dependencies."""
    try:
        manifest = build_manifest(target, include_timestamp=False)
        write_manifest(manifest, output)
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"Wrote [bold]{output}[/bold] with {len(manifest.skills)} skill(s).")


@app.command("diff")
def diff_manifests(
    old: Annotated[Path, typer.Argument(help="Trusted baseline manifest.")],
    new: Annotated[Path, typer.Argument(help="Newly generated manifest.")],
    json_output: Annotated[
        Path | None,
        typer.Option("--json-output", help="Optional machine-readable drift report."),
    ] = None,
    fail_on: Annotated[
        Severity | None,
        typer.Option(help="Exit 2 on drift at or above this severity."),
    ] = Severity.HIGH,
) -> None:
    """Compare two lockfiles and highlight capability or dependency drift."""
    try:
        drifts = compare_manifests(read_manifest(old), read_manifest(new))
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

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


@app.command()
def init(
    destination: Annotated[
        Path,
        typer.Argument(help="Directory for a minimal example skill."),
    ] = Path("example-skill"),
) -> None:
    """Create a specification-compliant starter skill."""
    if destination.exists() and any(destination.iterdir()):
        console.print(f"[bold red]error:[/bold red] {destination} is not empty")
        raise typer.Exit(1)
    destination.mkdir(parents=True, exist_ok=True)
    name = destination.name.lower().replace("_", "-").replace(" ", "-")
    content = f"""---
name: {name}
description: Describe what this skill does. Use when the user asks for a specific, repeatable task.
license: MIT
metadata:
  version: \"0.1.0\"
---

# {name}

## Workflow

1. Validate the input and state any assumptions.
2. Perform the task using the least-privileged tools necessary.
3. Verify the output before returning it.

## Safety

- Do not expose credentials or transmit private data.
- Ask for explicit approval before destructive or irreversible actions.
"""
    (destination / "SKILL.md").write_text(content, encoding="utf-8")
    console.print(f"Created [bold]{destination / 'SKILL.md'}[/bold]")


@app.command()
def gate(
    target: Annotated[Path, typer.Argument(help="Skill directory, SKILL.md, or skills root.")],
    policy: Annotated[
        Path,
        typer.Option("--policy", "-p", help="Policy-as-code YAML file."),
    ] = Path("skillbom.policy.yml"),
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: text, json, or sarif."),
    ] = "text",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write JSON/SARIF output to a file."),
    ] = None,
    fail_on: Annotated[
        Severity | None,
        typer.Option(help="Exit 2 when a policy violation reaches this severity."),
    ] = Severity.HIGH,
    as_of: Annotated[
        str | None,
        typer.Option("--as-of", help="Evaluate exception grants on YYYY-MM-DD instead of today."),
    ] = None,
) -> None:
    """Enforce a least-privilege policy against one or more Agent Skills."""
    try:
        manifest = build_manifest(target)
        loaded_policy = read_policy(policy)
        evaluation_date = date.fromisoformat(as_of) if as_of else None
        violations = evaluate_policy(manifest, loaded_policy, as_of=evaluation_date)
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    normalized = format.lower()
    if normalized == "text":
        print_policy_violations(violations, console)
    elif normalized == "json":
        write_json(
            [
                {
                    "rule_id": item.rule_id,
                    "severity": item.severity.value,
                    "skill": item.skill,
                    "subject": item.subject,
                    "message": item.message,
                    "evidence": (
                        {
                            "file": item.evidence.file,
                            "line": item.evidence.line,
                            "snippet": item.evidence.snippet,
                        }
                        if item.evidence
                        else None
                    ),
                }
                for item in violations
            ],
            output,
            console,
        )
    elif normalized == "sarif":
        write_json(policy_violations_to_sarif(manifest, violations), output, console)
    else:
        console.print("[bold red]error:[/bold red] --format must be text, json, or sarif")
        raise typer.Exit(1)

    if fail_on is not None and any(
        item.severity.rank >= fail_on.rank for item in violations
    ):
        raise typer.Exit(2)


@app.command("init-policy")
def init_policy(
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Policy file path."),
    ] = Path("skillbom.policy.yml"),
    force: Annotated[
        bool,
        typer.Option("--force", help="Replace an existing policy file."),
    ] = False,
) -> None:
    """Create a documented least-privilege policy template."""
    try:
        write_default_policy(output, force=force)
    except OSError as exc:
        console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"Created [bold]{output}[/bold]")
