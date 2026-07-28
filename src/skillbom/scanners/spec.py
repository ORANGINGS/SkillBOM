from __future__ import annotations

import re
from pathlib import Path

from skillbom.models import Evidence, Finding, Severity
from skillbom.parser import ParsedSkill
from skillbom.utils import clean_snippet

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\((?P<target>[^)]+)\)")
TRIGGER_HINTS = (
    "use when",
    "when asked",
    "when the user",
    "when handling",
    "when working",
    "appropriate for",
    "用於",
    "適用於",
    "當使用者",
    "需要時",
    "處理",
)


def _finding(
    rule_id: str,
    severity: Severity,
    title: str,
    message: str,
    parsed: ParsedSkill,
    remediation: str,
    line: int = 1,
    snippet: str = "SKILL.md",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category="spec",
        title=title,
        message=message,
        evidence=Evidence("SKILL.md", line, clean_snippet(snippet)),
        remediation=remediation,
    )


def scan_spec(parsed: ParsedSkill) -> list[Finding]:
    findings: list[Finding] = []
    metadata = parsed.metadata

    if parsed.parse_error:
        findings.append(
            _finding(
                "SPEC-001",
                Severity.HIGH,
                "Invalid frontmatter",
                parsed.parse_error,
                parsed,
                "Add valid YAML frontmatter with required name and description fields.",
            )
        )
        return findings

    name = metadata.get("name")
    description = metadata.get("description")

    if not isinstance(name, str) or not name:
        findings.append(
            _finding(
                "SPEC-002",
                Severity.HIGH,
                "Missing skill name",
                "The required frontmatter field 'name' is missing or is not a string.",
                parsed,
                "Set name to the lowercase kebab-case skill directory name.",
            )
        )
    else:
        if len(name) > 64 or not NAME_RE.fullmatch(name):
            findings.append(
                _finding(
                    "SPEC-003",
                    Severity.HIGH,
                    "Invalid skill name",
                    "Skill names must be 1-64 lowercase letters, numbers, or single hyphens.",
                    parsed,
                    "Rename the skill using lowercase kebab-case without consecutive hyphens.",
                    snippet=f"name: {name}",
                )
            )
        if name != parsed.root.name:
            findings.append(
                _finding(
                    "SPEC-004",
                    Severity.MEDIUM,
                    "Directory/name mismatch",
                    f"Frontmatter name '{name}' does not match directory '{parsed.root.name}'.",
                    parsed,
                    "Make the directory name and frontmatter name identical.",
                    snippet=f"name: {name}",
                )
            )

    if not isinstance(description, str) or not description.strip():
        findings.append(
            _finding(
                "SPEC-005",
                Severity.HIGH,
                "Missing description",
                "The required frontmatter field 'description' is missing or empty.",
                parsed,
                "Describe what the skill does and the situations that should activate it.",
            )
        )
    else:
        if len(description) > 1024:
            findings.append(
                _finding(
                    "SPEC-006",
                    Severity.HIGH,
                    "Description too long",
                    "The description exceeds the 1024-character specification limit.",
                    parsed,
                    "Shorten the description to 1024 characters or fewer.",
                    snippet=f"description: {description[:100]}",
                )
            )
        lowered = description.lower()
        if not any(hint in lowered for hint in TRIGGER_HINTS):
            findings.append(
                _finding(
                    "QUALITY-001",
                    Severity.LOW,
                    "Weak activation guidance",
                    "The description explains the capability but not clearly when an agent should use it.",
                    parsed,
                    "Add an explicit phrase such as 'Use when...' with concrete task keywords.",
                    snippet=f"description: {description[:120]}",
                )
            )

    compatibility = metadata.get("compatibility")
    if compatibility is not None and (
        not isinstance(compatibility, str) or not 1 <= len(compatibility) <= 500
    ):
        findings.append(
            _finding(
                "SPEC-007",
                Severity.MEDIUM,
                "Invalid compatibility field",
                "compatibility must be a non-empty string of at most 500 characters.",
                parsed,
                "Use a short string describing required products, packages, network, or OS constraints.",
            )
        )

    metadata_extra = metadata.get("metadata")
    if metadata_extra is not None:
        if not isinstance(metadata_extra, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in metadata_extra.items()
        ):
            findings.append(
                _finding(
                    "SPEC-008",
                    Severity.MEDIUM,
                    "Non-portable metadata",
                    "The open specification defines metadata as a string-to-string mapping.",
                    parsed,
                    "Convert metadata keys and values to strings for cross-client compatibility.",
                )
            )

    allowed_tools = metadata.get("allowed-tools")
    if allowed_tools is not None and not isinstance(allowed_tools, str):
        findings.append(
            _finding(
                "PORTABILITY-001",
                Severity.LOW,
                "Non-portable allowed-tools format",
                "The open Agent Skills specification uses a space-separated string for allowed-tools.",
                parsed,
                "Use a space-separated string unless intentionally targeting a client-specific extension.",
            )
        )

    if not parsed.body.strip():
        findings.append(
            _finding(
                "QUALITY-002",
                Severity.HIGH,
                "Empty instructions",
                "SKILL.md has no instruction body after frontmatter.",
                parsed,
                "Add concrete steps, examples, constraints, and edge-case handling.",
            )
        )
    else:
        body_lines = parsed.body.count("\n") + 1
        if body_lines > 500:
            findings.append(
                _finding(
                    "QUALITY-003",
                    Severity.LOW,
                    "Oversized SKILL.md",
                    f"The body has {body_lines} lines; the specification recommends fewer than 500.",
                    parsed,
                    "Move detailed material into focused files under references/.",
                    line=parsed.body_start_line,
                )
            )
        if not re.search(r"^#{1,3}\s+", parsed.body, re.MULTILINE):
            findings.append(
                _finding(
                    "QUALITY-004",
                    Severity.INFO,
                    "Unstructured instructions",
                    "The instruction body contains no Markdown headings.",
                    parsed,
                    "Use headings to separate workflow, constraints, examples, and failure handling.",
                    line=parsed.body_start_line,
                )
            )

    for match in MARKDOWN_LINK_RE.finditer(parsed.body):
        target = match.group("target").strip().split("#", 1)[0]
        if not target or target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        candidate = (parsed.root / target).resolve()
        try:
            candidate.relative_to(parsed.root.resolve())
        except ValueError:
            findings.append(
                _finding(
                    "SEC-PATH-001",
                    Severity.MEDIUM,
                    "Reference escapes skill directory",
                    f"Relative reference '{target}' resolves outside the skill root.",
                    parsed,
                    "Keep references within the skill directory and avoid '../' traversal.",
                    line=parsed.body_start_line + parsed.body[: match.start()].count("\n"),
                    snippet=match.group(0),
                )
            )
            continue
        if not candidate.exists():
            findings.append(
                _finding(
                    "QUALITY-005",
                    Severity.MEDIUM,
                    "Broken file reference",
                    f"Referenced file '{target}' does not exist.",
                    parsed,
                    "Fix the relative path or add the missing file.",
                    line=parsed.body_start_line + parsed.body[: match.start()].count("\n"),
                    snippet=match.group(0),
                )
            )

    return findings


def is_spec_valid(findings: list[Finding]) -> bool:
    return not any(
        item.category == "spec" and item.severity.rank >= Severity.MEDIUM.rank
        for item in findings
    )
