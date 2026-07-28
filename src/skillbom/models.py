from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


@dataclass(slots=True, frozen=True)
class Evidence:
    file: str
    line: int
    snippet: str


@dataclass(slots=True, frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    category: str
    title: str
    message: str
    evidence: Evidence
    remediation: str


@dataclass(slots=True, frozen=True)
class Capability:
    name: str
    evidence: tuple[Evidence, ...] = ()


@dataclass(slots=True, frozen=True)
class Dependency:
    kind: str
    name: str
    evidence: Evidence


@dataclass(slots=True, frozen=True)
class FileRecord:
    path: str
    sha256: str
    size: int


@dataclass(slots=True)
class SkillRecord:
    name: str
    path: str
    metadata: dict[str, Any]
    spec_valid: bool
    score: int
    capabilities: list[Capability] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files: list[FileRecord] = field(default_factory=list)
    digest: str = ""


@dataclass(slots=True)
class Manifest:
    schema_version: str
    generated_at: str | None
    target: str
    tool: dict[str, str]
    skills: list[SkillRecord]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class Drift:
    kind: str
    severity: Severity
    skill: str
    item: str
    message: str
