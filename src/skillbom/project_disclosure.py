from __future__ import annotations

import re
from pathlib import Path

from skillbom.models import Capability, Dependency, Evidence, Finding, Severity
from skillbom.utils import iter_files, read_text, relative

DOCUMENT_NAMES = {"readme.md", "security.md", "skill.md"}
DISCLOSURE_KEYWORDS = {
    "process-execution": ("shell", "command", "terminal", "subprocess", "execute process"),
    "code-execution": ("eval", "dynamic code", "execute code", "code execution"),
    "credential-access": ("credential", "token", "api key", "secret", "environment variable"),
    "network-access": ("network", "outbound", "http", "external service", "internet"),
    "filesystem-write": ("write file", "modify file", "edit file", "create file"),
    "destructive-filesystem": ("delete file", "remove file", "recursive deletion"),
    "destructive-vcs": ("force push", "hard reset", "git clean"),
    "privileged-operation": ("sudo", "administrator", "elevated privilege", "root access"),
}
HIGH_IMPACT_CAPABILITIES = {
    "process-execution",
    "code-execution",
    "credential-access",
    "destructive-filesystem",
    "destructive-vcs",
    "privileged-operation",
}


def scan_disclosure_gaps(
    capabilities: list[Capability], dependencies: list[Dependency], *, declared_text: str
) -> list[Finding]:
    findings: list[Finding] = []
    for capability in capabilities:
        keywords = DISCLOSURE_KEYWORDS.get(capability.name)
        if not keywords or any(keyword in declared_text for keyword in keywords):
            continue
        evidence = capability.evidence[0] if capability.evidence else Evidence(".", 1, capability.name)
        severity = Severity.HIGH if capability.name in HIGH_IMPACT_CAPABILITIES else Severity.MEDIUM
        findings.append(
            Finding(
                "DISCLOSURE-CAPABILITY-001",
                severity,
                "disclosure",
                "Observed capability is not documented",
                f"Capability '{capability.name}' was observed in code but not disclosed in project documentation.",
                evidence,
                "Document affected data, destinations, safeguards, and user approval requirements.",
            )
        )
    documented_domains = set(re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", declared_text))
    for dependency in dependencies:
        if dependency.kind != "service" or dependency.name.lower() in documented_domains:
            continue
        findings.append(
            Finding(
                "DISCLOSURE-SERVICE-001",
                Severity.MEDIUM,
                "disclosure",
                "External service is not documented",
                f"External domain '{dependency.name}' appears in code/configuration but not documentation.",
                dependency.evidence,
                "Declare the domain, transmitted data, authentication method, and retention expectations.",
            )
        )
    return _dedupe_findings(findings)


def documentation_text(root: Path) -> str:
    chunks: list[str] = []
    for path in iter_files(root):
        if path.is_symlink():
            continue
        rel = relative(path, root).lower()
        if path.name.lower() in DOCUMENT_NAMES or (
            rel.startswith("docs/") and path.suffix.lower() == ".md"
        ):
            text = read_text(path)
            if text:
                chunks.append(text.lower())
    return "\n".join(chunks)


def filter_project_dependencies(items: list[Dependency]) -> list[Dependency]:
    return [
        item
        for item in items
        if not (item.kind == "service" and _is_documentation_path(item.evidence.file))
    ]


def _is_documentation_path(value: str) -> bool:
    path = value.lower()
    return Path(path).name in DOCUMENT_NAMES or path.startswith("docs/")


def _dedupe_findings(items: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, str]] = set()
    result: list[Finding] = []
    for item in items:
        key = (item.rule_id, item.evidence.file, item.evidence.line, item.message)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result
