from __future__ import annotations

from pathlib import Path

from skillbom.models import Capability, Evidence, Finding, Severity
from skillbom.project_code_rules import scan_code_behaviors
from skillbom.project_install_rules import scan_install_hooks
from skillbom.project_types import discover_exposed_tools


def scan_project_specific_security(
    root: Path, project_types: list[str]
) -> tuple[list[Finding], list[Capability]]:
    install_findings, install_caps = scan_install_hooks(root)
    code_findings, code_caps = scan_code_behaviors(root)
    findings = [*install_findings, *code_findings]
    evidence: dict[str, list[Evidence]] = {}
    for source in (install_caps, code_caps):
        for name, items in source.items():
            evidence.setdefault(name, []).extend(items)

    if "mcp-server" in project_types:
        high_impact = {
            "process-execution",
            "code-execution",
            "credential-access",
            "destructive-filesystem",
            "privileged-operation",
        }
        for tool in discover_exposed_tools(root):
            file_caps = {
                capability
                for capability, items in evidence.items()
                if any(item.file == tool.evidence.file for item in items)
            }
            relevant = file_caps & high_impact
            if relevant:
                findings.append(
                    Finding(
                        "MCP-TOOL-HIGH-IMPACT-001",
                        Severity.HIGH,
                        "mcp-tool",
                        "MCP tool shares code with high-impact behavior",
                        f"Exposed MCP tool '{tool.name}' is defined with: {', '.join(sorted(relevant))}.",
                        tool.evidence,
                        "Place privileged behavior behind validation, approval, and least-privilege policy checks.",
                    )
                )

    capabilities = [
        Capability(name, tuple(_dedupe_evidence(items)))
        for name, items in sorted(evidence.items())
    ]
    return _dedupe_findings(findings), capabilities


def _dedupe_findings(items: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, str]] = set()
    result: list[Finding] = []
    for item in items:
        key = (item.rule_id, item.evidence.file, item.evidence.line, item.message)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _dedupe_evidence(items: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, int, str]] = set()
    result: list[Evidence] = []
    for item in items:
        key = (item.file, item.line, item.snippet)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result
