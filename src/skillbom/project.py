from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from skillbom import __version__
from skillbom.manifest import DEDUCTIONS
from skillbom.models import Capability, Dependency, Evidence, FileRecord, Finding, Severity
from skillbom.parser import discover_skills
from skillbom.project_security import (
    DISCLOSURE_KEYWORDS,
    HIGH_IMPACT_CAPABILITIES,
    documentation_text,
    filter_project_dependencies,
    scan_disclosure_gaps,
    scan_project_specific_security,
)
from skillbom.project_types import ExposedTool, detect_project_types, discover_exposed_tools
from skillbom.scanners import scan_dependencies, scan_security
from skillbom.utils import iter_files, relative, sha256_file

PROJECT_SCHEMA_VERSION = "0.1"

@dataclass(slots=True)
class ProjectReport:
    schema_version: str
    generated_at: str | None
    target: str
    source: dict[str, str]
    tool: dict[str, str]
    name: str
    project_types: list[str]
    score: int
    capabilities: list[Capability] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files: list[FileRecord] = field(default_factory=list)
    discovered_skills: list[str] = field(default_factory=list)
    exposed_tools: list[ExposedTool] = field(default_factory=list)
    declared_capabilities: list[str] = field(default_factory=list)
    digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_project_report(
    root: Path,
    *,
    target: str | None = None,
    source: dict[str, str] | None = None,
    include_timestamp: bool = True,
) -> ProjectReport:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"Project root is not a directory: {root}")

    base_findings, base_capabilities = scan_security(root)
    base_dependencies = filter_project_dependencies(scan_dependencies(root, {}))
    project_types = detect_project_types(root)
    project_findings, project_capabilities = scan_project_specific_security(root, project_types)
    exposed_tools = discover_exposed_tools(root)

    capabilities = _merge_capabilities([*base_capabilities, *project_capabilities])
    dependencies = _dedupe_dependencies(
        [*base_dependencies, *(_tools_as_dependencies(exposed_tools))]
    )
    declared_text = documentation_text(root)
    declared_capabilities = sorted(
        capability
        for capability, keywords in DISCLOSURE_KEYWORDS.items()
        if any(keyword in declared_text for keyword in keywords)
    )
    disclosure_findings = scan_disclosure_gaps(
        capabilities,
        dependencies,
        declared_text=declared_text,
    )
    findings = _dedupe_findings([*base_findings, *project_findings, *disclosure_findings])
    findings.sort(
        key=lambda item: (-item.severity.rank, item.rule_id, item.evidence.file, item.evidence.line)
    )

    files = [
        FileRecord(relative(path, root), sha256_file(path), path.stat().st_size)
        for path in iter_files(root)
        if not path.is_symlink()
    ]
    digest_input = json.dumps(
        [{"path": item.path, "sha256": item.sha256} for item in files],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(digest_input).hexdigest()
    score = max(0, 100 - sum(DEDUCTIONS[item.severity] for item in findings))
    discovered_skills = [relative(skill_root, root) for skill_root in discover_skills(root)]
    name = (source or {}).get("repository", root.name).split("/")[-1]
    return ProjectReport(
        schema_version=PROJECT_SCHEMA_VERSION,
        generated_at=datetime.now(UTC).isoformat() if include_timestamp else None,
        target=target or root.as_posix(),
        source=dict(source or {"kind": "local"}),
        tool={"name": "skillbom", "version": __version__},
        name=name,
        project_types=project_types,
        score=score,
        capabilities=capabilities,
        dependencies=dependencies,
        findings=findings,
        files=files,
        discovered_skills=discovered_skills,
        exposed_tools=exposed_tools,
        declared_capabilities=declared_capabilities,
        digest=digest,
    )



def _tools_as_dependencies(tools: list[ExposedTool]) -> list[Dependency]:
    return [Dependency("mcp-tool", tool.name, tool.evidence) for tool in tools]


def _merge_capabilities(items: list[Capability]) -> list[Capability]:
    evidence: dict[str, list[Evidence]] = {}
    for item in items:
        evidence.setdefault(item.name, []).extend(item.evidence)
    return [
        Capability(name, tuple(_dedupe_evidence(values)))
        for name, values in sorted(evidence.items())
    ]


def _dedupe_dependencies(items: list[Dependency]) -> list[Dependency]:
    seen: set[tuple[str, str]] = set()
    result: list[Dependency] = []
    for item in items:
        key = (item.kind, item.name)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return sorted(result, key=lambda item: (item.kind, item.name))



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



def compare_project_reports(old: dict[str, Any], new: dict[str, Any]):  # type: ignore[no-untyped-def]
    from skillbom.models import Drift

    project_name = str(new.get("name") or old.get("name") or "repository")
    drifts: list[Drift] = []
    old_types = set(old.get("project_types", []))
    new_types = set(new.get("project_types", []))
    for project_type in sorted(new_types - old_types):
        drifts.append(
            Drift(
                "project-type-added",
                Severity.MEDIUM,
                project_name,
                str(project_type),
                f"Repository is newly classified as '{project_type}'.",
            )
        )

    old_caps = {item["name"] for item in old.get("capabilities", []) if isinstance(item, dict) and "name" in item}
    new_caps = {item["name"] for item in new.get("capabilities", []) if isinstance(item, dict) and "name" in item}
    for capability in sorted(new_caps - old_caps):
        severity = Severity.HIGH if capability in HIGH_IMPACT_CAPABILITIES else Severity.MEDIUM
        drifts.append(
            Drift(
                "capability-added",
                severity,
                project_name,
                capability,
                f"Repository gained capability '{capability}'.",
            )
        )
    for capability in sorted(old_caps - new_caps):
        drifts.append(
            Drift(
                "capability-removed",
                Severity.INFO,
                project_name,
                capability,
                f"Repository no longer exposes capability '{capability}'.",
            )
        )

    old_deps = {
        (item["kind"], item["name"])
        for item in old.get("dependencies", [])
        if isinstance(item, dict) and "kind" in item and "name" in item
    }
    new_deps = {
        (item["kind"], item["name"])
        for item in new.get("dependencies", [])
        if isinstance(item, dict) and "kind" in item and "name" in item
    }
    for kind, name in sorted(new_deps - old_deps):
        severity = Severity.HIGH if kind == "mcp-tool" else Severity.MEDIUM if kind == "service" else Severity.LOW
        drifts.append(
            Drift(
                "dependency-added",
                severity,
                project_name,
                f"{kind}:{name}",
                f"Repository gained dependency '{kind}:{name}'.",
            )
        )

    old_findings = {
        (item.get("rule_id"), item.get("evidence", {}).get("file"))
        for item in old.get("findings", [])
        if isinstance(item, dict)
    }
    for item in new.get("findings", []):
        if not isinstance(item, dict):
            continue
        key = (item.get("rule_id"), item.get("evidence", {}).get("file"))
        severity_value = item.get("severity")
        if key not in old_findings and severity_value in {"high", "critical"}:
            drifts.append(
                Drift(
                    "high-finding-added",
                    Severity(str(severity_value)),
                    project_name,
                    str(item.get("rule_id", "unknown")),
                    f"New {severity_value} finding {item.get('rule_id')}: {item.get('title', '')}",
                )
            )

    if old.get("digest") != new.get("digest"):
        drifts.append(
            Drift(
                "content-changed",
                Severity.INFO,
                project_name,
                "digest",
                "Repository content digest changed.",
            )
        )
    return sorted(drifts, key=lambda item: (-item.severity.rank, item.skill, item.kind, item.item))
