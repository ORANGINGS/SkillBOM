from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from skillbom.models import Manifest, PolicyViolation, Severity, SkillRecord

DEFAULT_POLICY = """# yaml-language-server: $schema=./schemas/skillbom-policy.schema.json\nschema-version: "1"
defaults:
  require-spec-valid: true
  max-finding-severity: medium
  denied-capabilities:
    - embedded-secret
    - code-execution
    - privileged-operation
    - destructive-filesystem
    - destructive-vcs
  allowed-services:
    - github.com
    - api.github.com
  allowed-agent-tools:
    - Read
    - Grep
    - Glob

skills:
  example-skill:
    capability-exceptions:
      - process-execution
    service-exceptions:
      - uploads.example.com
"""

_ALLOWED_RULE_KEYS = {
    "require-spec-valid",
    "max-finding-severity",
    "denied-capabilities",
    "allowed-services",
    "allowed-agent-tools",
    "capability-exceptions",
    "service-exceptions",
    "agent-tool-exceptions",
}


@dataclass(slots=True, frozen=True)
class PolicyRules:
    require_spec_valid: bool | None = None
    max_finding_severity: Severity | None = None
    denied_capabilities: tuple[str, ...] = ()
    allowed_services: tuple[str, ...] | None = None
    allowed_agent_tools: tuple[str, ...] | None = None
    capability_exceptions: tuple[str, ...] = ()
    service_exceptions: tuple[str, ...] = ()
    agent_tool_exceptions: tuple[str, ...] = ()


@dataclass(slots=True, frozen=True)
class Policy:
    schema_version: str
    defaults: PolicyRules
    skills: dict[str, PolicyRules]


def read_policy(path: Path) -> Policy:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Policy must be a YAML mapping.")

    unknown_top = set(raw) - {"schema-version", "version", "defaults", "skills"}
    if unknown_top:
        raise ValueError(f"Unknown policy keys: {', '.join(sorted(unknown_top))}")

    schema_version = raw.get("schema-version", raw.get("version", "1"))
    if str(schema_version) != "1":
        raise ValueError(f"Unsupported policy schema version: {schema_version}")

    defaults_raw = raw.get("defaults", {})
    defaults = _parse_rules(defaults_raw, "defaults")

    skills_raw = raw.get("skills", {})
    if not isinstance(skills_raw, dict):
        raise ValueError("Policy 'skills' must be a mapping of skill names to rules.")
    skills: dict[str, PolicyRules] = {}
    for name, value in skills_raw.items():
        if not isinstance(name, str) or not name:
            raise ValueError("Policy skill names must be non-empty strings.")
        skills[name] = _parse_rules(value, f"skills.{name}")

    return Policy("1", defaults, skills)


def write_default_policy(path: Path, *, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists; pass --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(DEFAULT_POLICY, encoding="utf-8")


def evaluate_policy(manifest: Manifest, policy: Policy) -> list[PolicyViolation]:
    violations: list[PolicyViolation] = []
    for skill in manifest.skills:
        rules = _merge_rules(policy.defaults, policy.skills.get(skill.name))
        violations.extend(_evaluate_skill(skill, rules))
    return sorted(
        violations,
        key=lambda item: (-item.severity.rank, item.skill, item.rule_id, item.subject),
    )


def _evaluate_skill(skill: SkillRecord, rules: PolicyRules) -> list[PolicyViolation]:
    violations: list[PolicyViolation] = []

    if rules.require_spec_valid and not skill.spec_valid:
        evidence = next(
            (item.evidence for item in skill.findings if item.rule_id.startswith("SPEC-")),
            None,
        )
        violations.append(
            PolicyViolation(
                "POLICY-SPEC-001",
                Severity.HIGH,
                skill.name,
                "spec-valid",
                "Skill does not satisfy the Agent Skills specification required by policy.",
                evidence,
            )
        )

    if rules.max_finding_severity is not None:
        for finding in skill.findings:
            if finding.severity.rank > rules.max_finding_severity.rank:
                violations.append(
                    PolicyViolation(
                        "POLICY-FINDING-001",
                        finding.severity,
                        skill.name,
                        finding.rule_id,
                        (
                            f"Finding {finding.rule_id} is {finding.severity.value}, above the "
                            f"policy maximum {rules.max_finding_severity.value}."
                        ),
                        finding.evidence,
                    )
                )

    for capability in skill.capabilities:
        if _matches_any(capability.name, rules.denied_capabilities) and not _matches_any(
            capability.name, rules.capability_exceptions
        ):
            violations.append(
                PolicyViolation(
                    "POLICY-CAPABILITY-001",
                    Severity.HIGH,
                    skill.name,
                    capability.name,
                    f"Capability '{capability.name}' is denied by policy.",
                    capability.evidence[0] if capability.evidence else None,
                )
            )

    for dependency in skill.dependencies:
        if dependency.kind == "service" and rules.allowed_services is not None:
            allowed = (*rules.allowed_services, *rules.service_exceptions)
            if not _matches_any(dependency.name, allowed):
                violations.append(
                    PolicyViolation(
                        "POLICY-SERVICE-001",
                        Severity.HIGH,
                        skill.name,
                        dependency.name,
                        f"External service '{dependency.name}' is not allowlisted by policy.",
                        dependency.evidence,
                    )
                )
        elif dependency.kind == "agent-tool" and rules.allowed_agent_tools is not None:
            allowed = (*rules.allowed_agent_tools, *rules.agent_tool_exceptions)
            if not _matches_any(dependency.name, allowed):
                violations.append(
                    PolicyViolation(
                        "POLICY-AGENT-TOOL-001",
                        Severity.HIGH,
                        skill.name,
                        dependency.name,
                        f"Agent tool '{dependency.name}' is not allowlisted by policy.",
                        dependency.evidence,
                    )
                )

    return violations


def _parse_rules(value: Any, location: str) -> PolicyRules:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError(f"Policy '{location}' must be a mapping.")
    unknown = set(value) - _ALLOWED_RULE_KEYS
    if unknown:
        raise ValueError(f"Unknown keys in {location}: {', '.join(sorted(unknown))}")

    require_spec_valid = value.get("require-spec-valid")
    if require_spec_valid is not None and not isinstance(require_spec_valid, bool):
        raise ValueError(f"{location}.require-spec-valid must be true or false.")

    maximum = value.get("max-finding-severity")
    max_finding_severity = None
    if maximum is not None:
        try:
            max_finding_severity = Severity(str(maximum).lower())
        except ValueError as exc:
            raise ValueError(f"Invalid severity at {location}.max-finding-severity: {maximum}") from exc

    return PolicyRules(
        require_spec_valid=require_spec_valid,
        max_finding_severity=max_finding_severity,
        denied_capabilities=_string_list(value, "denied-capabilities", location) or (),
        allowed_services=_string_list(value, "allowed-services", location),
        allowed_agent_tools=_string_list(value, "allowed-agent-tools", location),
        capability_exceptions=_string_list(value, "capability-exceptions", location) or (),
        service_exceptions=_string_list(value, "service-exceptions", location) or (),
        agent_tool_exceptions=_string_list(value, "agent-tool-exceptions", location) or (),
    )


def _string_list(value: dict[str, Any], key: str, location: str) -> tuple[str, ...] | None:
    if key not in value:
        return None
    items = value[key]
    if not isinstance(items, list) or any(not isinstance(item, str) or not item for item in items):
        raise ValueError(f"{location}.{key} must be a list of non-empty strings.")
    return tuple(dict.fromkeys(items))


def _merge_rules(defaults: PolicyRules, override: PolicyRules | None) -> PolicyRules:
    override = override or PolicyRules()
    return PolicyRules(
        require_spec_valid=(
            override.require_spec_valid
            if override.require_spec_valid is not None
            else defaults.require_spec_valid if defaults.require_spec_valid is not None else True
        ),
        max_finding_severity=(
            override.max_finding_severity
            if override.max_finding_severity is not None
            else defaults.max_finding_severity
        ),
        denied_capabilities=_unique(
            (*defaults.denied_capabilities, *override.denied_capabilities)
        ),
        allowed_services=(
            override.allowed_services
            if override.allowed_services is not None
            else defaults.allowed_services
        ),
        allowed_agent_tools=(
            override.allowed_agent_tools
            if override.allowed_agent_tools is not None
            else defaults.allowed_agent_tools
        ),
        capability_exceptions=_unique(
            (*defaults.capability_exceptions, *override.capability_exceptions)
        ),
        service_exceptions=_unique((*defaults.service_exceptions, *override.service_exceptions)),
        agent_tool_exceptions=_unique(
            (*defaults.agent_tool_exceptions, *override.agent_tool_exceptions)
        ),
    )


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatchcase(value.lower(), pattern.lower()) for pattern in patterns)


def _unique(items: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))
