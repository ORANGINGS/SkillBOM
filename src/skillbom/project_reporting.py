from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from skillbom.models import Severity
from skillbom.project import ProjectReport
from skillbom.reporting import SEVERITY_STYLES


def print_project_report(report: ProjectReport, console: Console) -> None:
    capabilities = ", ".join(item.name for item in report.capabilities) or "none detected"
    project_types = ", ".join(report.project_types)
    source = report.source.get("repository", report.source.get("kind", "local"))
    summary = (
        f"[bold]{report.name}[/bold]  score=[bold]{report.score}/100[/bold]\n"
        f"Types: {project_types}\nSource: {source}\n"
        f"Capabilities: {capabilities}\n"
        f"MCP tools: {len(report.exposed_tools)}  Dependencies: {len(report.dependencies)}  "
        f"Files: {len(report.files)}  Findings: {len(report.findings)}"
    )
    console.print(Panel(summary, title=report.target, expand=False))
    if report.exposed_tools:
        tools = Table(title="Exposed MCP tools", show_header=True, header_style="bold")
        tools.add_column("Tool")
        tools.add_column("Framework")
        tools.add_column("Location")
        for tool in report.exposed_tools:
            tools.add_row(tool.name, tool.framework, f"{tool.evidence.file}:{tool.evidence.line}")
        console.print(tools)
    if report.findings:
        table = Table(title="Repository findings", show_header=True, header_style="bold")
        table.add_column("Severity", width=10)
        table.add_column("Rule", width=28)
        table.add_column("Location", width=28)
        table.add_column("Finding")
        for finding in report.findings:
            style = SEVERITY_STYLES[finding.severity]
            table.add_row(
                f"[{style}]{finding.severity.value.upper()}[/{style}]",
                finding.rule_id,
                f"{finding.evidence.file}:{finding.evidence.line}",
                f"{finding.title}: {finding.message}",
            )
        console.print(table)


def project_to_sarif(report: ProjectReport) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title.replace(" ", ""),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.message},
            "help": {"text": finding.remediation},
            "defaultConfiguration": {"level": _sarif_level(finding.severity)},
        }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": Path(finding.evidence.file).as_posix()},
                            "region": {
                                "startLine": finding.evidence.line,
                                "snippet": {"text": finding.evidence.snippet},
                            },
                        }
                    }
                ],
                "properties": {"projectTypes": report.project_types},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillBOM Repository Security Scan",
                        "version": report.tool["version"],
                        "informationUri": "https://github.com/ORANGINGS/SkillBOM",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _sarif_level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity in {Severity.MEDIUM, Severity.LOW}:
        return "warning"
    return "note"
