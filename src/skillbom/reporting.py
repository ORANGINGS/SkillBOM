from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from skillbom.models import Drift, Manifest, PolicyViolation, Severity

SEVERITY_STYLES = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
    Severity.CRITICAL: "bold white on red",
}


def print_manifest(manifest: Manifest, console: Console) -> None:
    for skill in manifest.skills:
        capabilities = ", ".join(item.name for item in skill.capabilities) or "none detected"
        summary = (
            f"[bold]{skill.name}[/bold]  score=[bold]{skill.score}/100[/bold]  "
            f"spec={'valid' if skill.spec_valid else 'invalid'}\n"
            f"Capabilities: {capabilities}\n"
            f"Dependencies: {len(skill.dependencies)}  Files: {len(skill.files)}  Findings: {len(skill.findings)}"
        )
        console.print(Panel(summary, title=skill.path or ".", expand=False))

        if skill.findings:
            table = Table(show_header=True, header_style="bold")
            table.add_column("Severity", width=10)
            table.add_column("Rule", width=20)
            table.add_column("Location", width=28)
            table.add_column("Finding")
            for finding in skill.findings:
                style = SEVERITY_STYLES[finding.severity]
                table.add_row(
                    f"[{style}]{finding.severity.value.upper()}[/{style}]",
                    finding.rule_id,
                    f"{finding.evidence.file}:{finding.evidence.line}",
                    f"{finding.title}: {finding.message}",
                )
            console.print(table)
        console.print()


def print_drifts(drifts: list[Drift], console: Console) -> None:
    if not drifts:
        console.print("[bold green]No capability or dependency drift detected.[/bold green]")
        return
    table = Table(title="SkillBOM drift report", show_header=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("Skill", width=22)
    table.add_column("Change", width=24)
    table.add_column("Details")
    for drift in drifts:
        style = SEVERITY_STYLES[drift.severity]
        table.add_row(
            f"[{style}]{drift.severity.value.upper()}[/{style}]",
            drift.skill,
            drift.kind,
            drift.message,
        )
    console.print(table)


def print_policy_violations(violations: list[PolicyViolation], console: Console) -> None:
    if not violations:
        console.print("[bold green]Policy gate passed.[/bold green]")
        return
    table = Table(title="SkillBOM policy gate", show_header=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("Skill", width=22)
    table.add_column("Policy rule", width=24)
    table.add_column("Location", width=28)
    table.add_column("Details")
    for violation in violations:
        style = SEVERITY_STYLES[violation.severity]
        location = (
            f"{violation.evidence.file}:{violation.evidence.line}"
            if violation.evidence
            else "-"
        )
        table.add_row(
            f"[{style}]{violation.severity.value.upper()}[/{style}]",
            violation.skill,
            violation.rule_id,
            location,
            violation.message,
        )
    console.print(table)


def policy_violations_to_sarif(
    manifest: Manifest, violations: list[PolicyViolation]
) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    skill_paths = {skill.name: skill.path for skill in manifest.skills}
    for violation in violations:
        rules[violation.rule_id] = {
            "id": violation.rule_id,
            "name": violation.rule_id.replace("-", ""),
            "shortDescription": {"text": violation.message},
            "defaultConfiguration": {"level": _sarif_level(violation.severity)},
        }
        result: dict[str, Any] = {
            "ruleId": violation.rule_id,
            "level": _sarif_level(violation.severity),
            "message": {"text": violation.message},
            "properties": {"skill": violation.skill, "subject": violation.subject},
        }
        if violation.evidence:
            base = skill_paths.get(violation.skill, "")
            location = (
                Path(base) / violation.evidence.file
                if base
                else Path(violation.evidence.file)
            )
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": location.as_posix()},
                        "region": {
                            "startLine": violation.evidence.line,
                            "snippet": {"text": violation.evidence.snippet},
                        },
                    }
                }
            ]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillBOM Policy Gate",
                        "version": manifest.tool["version"],
                        "informationUri": "https://github.com/ORANGINGS/SkillBOM",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def to_sarif(manifest: Manifest) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for skill in manifest.skills:
        for finding in skill.findings:
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.title.replace(" ", ""),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.message},
                "help": {"text": finding.remediation},
                "defaultConfiguration": {"level": _sarif_level(finding.severity)},
            }
            location = Path(skill.path) / finding.evidence.file if skill.path else Path(finding.evidence.file)
            results.append(
                {
                    "ruleId": finding.rule_id,
                    "level": _sarif_level(finding.severity),
                    "message": {"text": finding.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": location.as_posix()},
                                "region": {
                                    "startLine": finding.evidence.line,
                                    "snippet": {"text": finding.evidence.snippet},
                                },
                            }
                        }
                    ],
                }
            )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillBOM",
                        "version": manifest.tool["version"],
                        "informationUri": "https://github.com/ORANGINGS/skillbom",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_json(data: Any, output: Path | None, console: Console) -> None:
    text = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
        console.print(f"Wrote [bold]{output}[/bold]")
    else:
        console.print(text, markup=False, highlight=False, soft_wrap=True)


def _sarif_level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity in {Severity.MEDIUM, Severity.LOW}:
        return "warning"
    return "note"
