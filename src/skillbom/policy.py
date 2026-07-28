from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from skillbom.models import Manifest, PolicyViolation, Severity, SkillRecord

_EXCEPTION_KEYS = {
    "capability-exceptions",
    "service-exceptions",
    "agent-tool-exceptions",
}
_ALLOWED_RULE_KEYS = {
    "require-spec-valid",
    "max-finding-severity",
    "denied-capabilities",
    "allowed-services",
    "allowed-agent-tools",
    "exception-expiry-warning-days",
    "max-exception-days",
    "require-exception-ticket",
    "require-separation-of-duties",
    *_EXCEPTION_KEYS,
}


@dataclass(slots=True, frozen=True)
class ExceptionGrant:
    item: str
    reason: str
    owner: str
    approved_by: str
    approved_at: date | None
    expires_at: date | None
    ticket: str | None = None
    legacy: bool = False


@dataclass(slots=True, frozen=True)
class PolicyRules:
    require_spec_valid: bool | None = None
    max_finding_severity: Severity | None = None
    denied_capabilities: tuple[str, ...] = ()
    allowed_services: tuple[str, ...] | None = None
    allowed_agent_tools: tuple[str, ...] | None = None
    exception_expiry_warning_days: int | None = None
    max_exception_days: int | None = None
    require_exception_ticket: bool | None = None
    require_separation_of_duties: bool | None = None
    capability_exceptions: tuple[ExceptionGrant, ...] = ()
    service_exceptions: tuple[ExceptionGrant, ...] = ()
    agent_tool_exceptions: tuple[ExceptionGrant, ...] = ()


@dataclass(slots=True, frozen=True)
class Policy:
    schema_version: str
    defaults: PolicyRules
    skills: dict[str, PolicyRules]


def default_policy_text(*, as_of: date | None = None) -> str:
    approved_at = as_of or datetime.now(UTC).date()
    expires_at = approved_at + timedelta(days=90)
    return f'''# yaml-language-server: $schema=./schemas/skillbom-policy.schema.json
schema-version: "2"
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
  exception-expiry-warning-days: 14
  max-exception-days: 90
  require-exception-ticket: true
  require-separation-of-duties: true

# Skill-specific exception grants must be scoped and auditable:
# skills:
#   example-skill:
#     capability-exceptions:
#       - item: process-execution
#         reason: Required to invoke an approved deployment CLI.
#         owner: platform-team
#         approved-by: security-team
#         approved-at: {approved_at.isoformat()}
#         expires-at: {expires_at.isoformat()}
#         ticket: SEC-123
'''


def read_policy(path: Path) -> Policy:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Policy must be a YAML mapping.")

    unknown_top = set(raw) - {"schema-version", "version", "defaults", "skills"}
    if unknown_top:
        raise ValueError(f"Unknown policy keys: {', '.join(sorted(unknown_top))}")

    schema_version = str(raw.get("schema-version", raw.get("version", "1")))
    if schema_version not in {"1", "2"}:
        raise ValueError(f"Unsupported policy schema version: {schema_version}")

    defaults_raw = raw.get("defaults", {})
    defaults = _parse_rules(defaults_raw, "defaults", schema_version=schema_version)

    skills_raw = raw.get("skills", {})
    if not isinstance(skills_raw, dict):
        raise ValueError("Policy 'skills' must be a mapping of skill names to rules.")
    skills: dict[str, PolicyRules] = {}
    for name, value in skills_raw.items():
        if not isinstance(name, str) or not name:
            raise ValueError("Policy skill names must be non-empty strings.")
        skills[name] = _parse_rules(value, f"skills.{name}", schema_version=schema_version)

    return Policy(schema_version, defaults, skills)


def write_default_policy(path: Path, *, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists; pass --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(default_policy_text(), encoding="utf-8")


def evaluate_policy(
    manifest: Manifest,
    policy: Policy,
    *,
    as_of: date | None = None,
) -> list[PolicyViolation]:
    evaluation_date = as_of or datetime.now(UTC).date()
    violations: list[PolicyViolation] = []
    manifest_names = {skill.name for skill in manifest.skills}
    target_path = Path(manifest.target)
    scanned_inventory_root = target_path.is_dir() and not (target_path / "SKILL.md").exists()

    if scanned_inventory_root:
        for policy_skill in sorted(set(policy.skills) - manifest_names):
            violations.append(
                PolicyViolation(
                    "POLICY-SKILL-UNKNOWN-001",
                    Severity.HIGH,
                    policy_skill,
                    policy_skill,
                    "Policy contains rules for a skill that is not present in the scanned root.",
                )
            )

    for skill in manifest.skills:
        rules = _merge_rules(policy.defaults, policy.skills.get(skill.name))
        violations.extend(_evaluate_skill(skill, rules, as_of=evaluation_date))
    return sorted(
        violations,
        key=lambda item: (-item.severity.rank, item.skill, item.rule_id, item.subject),
    )


def _evaluate_skill(
    skill: SkillRecord,
    rules: PolicyRules,
    *,
    as_of: date,
) -> list[PolicyViolation]:
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

    capability_names = {item.name for item in skill.capabilities}
    service_names = {item.name for item in skill.dependencies if item.kind == "service"}
    agent_tool_names = {item.name for item in skill.dependencies if item.kind == "agent-tool"}

    denied_capabilities = {
        item for item in capability_names if _matches_any(item, rules.denied_capabilities)
    }
    unapproved_services = {
        item
        for item in service_names
        if rules.allowed_services is not None and not _matches_any(item, rules.allowed_services)
    }
    unapproved_agent_tools = {
        item
        for item in agent_tool_names
        if rules.allowed_agent_tools is not None
        and not _matches_any(item, rules.allowed_agent_tools)
    }

    capability_active, capability_declared, grant_violations = _audit_grants(
        skill.name,
        "capability",
        rules.capability_exceptions,
        denied_capabilities,
        rules,
        as_of,
    )
    violations.extend(grant_violations)
    service_active, service_declared, grant_violations = _audit_grants(
        skill.name,
        "service",
        rules.service_exceptions,
        unapproved_services,
        rules,
        as_of,
    )
    violations.extend(grant_violations)
    tool_active, tool_declared, grant_violations = _audit_grants(
        skill.name,
        "agent-tool",
        rules.agent_tool_exceptions,
        unapproved_agent_tools,
        rules,
        as_of,
    )
    violations.extend(grant_violations)

    for capability in skill.capabilities:
        if capability.name not in denied_capabilities:
            continue
        if _matches_any(capability.name, capability_active):
            continue
        if _matches_any(capability.name, capability_declared):
            continue
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
        if dependency.kind == "service" and dependency.name in unapproved_services:
            if _matches_any(dependency.name, service_active):
                continue
            if _matches_any(dependency.name, service_declared):
                continue
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
        elif dependency.kind == "agent-tool" and dependency.name in unapproved_agent_tools:
            if _matches_any(dependency.name, tool_active):
                continue
            if _matches_any(dependency.name, tool_declared):
                continue
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


def _audit_grants(
    skill_name: str,
    category: str,
    grants: tuple[ExceptionGrant, ...],
    required_items: set[str],
    rules: PolicyRules,
    as_of: date,
) -> tuple[tuple[str, ...], tuple[str, ...], list[PolicyViolation]]:
    active: list[str] = []
    declared = tuple(grant.item for grant in grants)
    violations: list[PolicyViolation] = []

    for grant in grants:
        invalid = False
        if grant.legacy:
            invalid = True
            violations.append(
                _grant_violation(
                    "POLICY-EXCEPTION-LEGACY-001",
                    Severity.HIGH,
                    skill_name,
                    grant,
                    "Legacy string exceptions are not enforceable grants; migrate to schema version 2.",
                )
            )
            continue

        assert grant.approved_at is not None
        assert grant.expires_at is not None

        if rules.require_exception_ticket and not grant.ticket:
            invalid = True
            violations.append(
                _grant_violation(
                    "POLICY-EXCEPTION-TICKET-001",
                    Severity.HIGH,
                    skill_name,
                    grant,
                    "Exception grant is missing the ticket required by policy.",
                )
            )

        if rules.require_separation_of_duties and grant.owner.casefold() == grant.approved_by.casefold():
            invalid = True
            violations.append(
                _grant_violation(
                    "POLICY-EXCEPTION-SEPARATION-001",
                    Severity.HIGH,
                    skill_name,
                    grant,
                    "Exception owner and approver must be different identities.",
                )
            )

        duration_days = (grant.expires_at - grant.approved_at).days
        if rules.max_exception_days is not None and duration_days > rules.max_exception_days:
            invalid = True
            violations.append(
                _grant_violation(
                    "POLICY-EXCEPTION-DURATION-001",
                    Severity.HIGH,
                    skill_name,
                    grant,
                    (
                        f"Exception lifetime is {duration_days} days, above the policy maximum "
                        f"of {rules.max_exception_days} days."
                    ),
                )
            )

        if grant.approved_at > as_of:
            invalid = True
            violations.append(
                _grant_violation(
                    "POLICY-EXCEPTION-NOT-YET-VALID-001",
                    Severity.HIGH,
                    skill_name,
                    grant,
                    f"Exception is approved in the future on {grant.approved_at.isoformat()}.",
                )
            )
        elif grant.expires_at < as_of:
            invalid = True
            violations.append(
                _grant_violation(
                    "POLICY-EXCEPTION-EXPIRED-001",
                    Severity.HIGH,
                    skill_name,
                    grant,
                    f"Exception expired on {grant.expires_at.isoformat()}.",
                )
            )
        else:
            remaining_days = (grant.expires_at - as_of).days
            warning_days = rules.exception_expiry_warning_days
            if warning_days is not None and remaining_days <= warning_days:
                violations.append(
                    _grant_violation(
                        "POLICY-EXCEPTION-EXPIRING-001",
                        Severity.MEDIUM,
                        skill_name,
                        grant,
                        (
                            f"Exception expires in {remaining_days} day(s) on "
                            f"{grant.expires_at.isoformat()}."
                        ),
                    )
                )

        if not any(_matches_any(item, (grant.item,)) for item in required_items):
            violations.append(
                _grant_violation(
                    "POLICY-EXCEPTION-UNUSED-001",
                    Severity.LOW,
                    skill_name,
                    grant,
                    (
                        f"{category} exception does not match any currently blocked "
                        "capability or dependency."
                    ),
                )
            )

        if not invalid:
            active.append(grant.item)

    return tuple(active), declared, violations


def _grant_violation(
    rule_id: str,
    severity: Severity,
    skill_name: str,
    grant: ExceptionGrant,
    message: str,
) -> PolicyViolation:
    ticket = f" ticket={grant.ticket}" if grant.ticket else ""
    return PolicyViolation(
        rule_id,
        severity,
        skill_name,
        grant.item,
        f"{message} owner={grant.owner or 'unknown'} approver={grant.approved_by or 'unknown'}{ticket}",
    )


def _parse_rules(value: Any, location: str, *, schema_version: str) -> PolicyRules:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError(f"Policy '{location}' must be a mapping.")
    unknown = set(value) - _ALLOWED_RULE_KEYS
    if unknown:
        raise ValueError(f"Unknown keys in {location}: {', '.join(sorted(unknown))}")
    if schema_version == "2" and location == "defaults" and set(value) & _EXCEPTION_KEYS:
        raise ValueError("Schema version 2 exceptions must be scoped under skills.<name>.")

    require_spec_valid = _optional_bool(value, "require-spec-valid", location)
    require_exception_ticket = _optional_bool(value, "require-exception-ticket", location)
    require_separation_of_duties = _optional_bool(
        value, "require-separation-of-duties", location
    )

    maximum = value.get("max-finding-severity")
    max_finding_severity = None
    if maximum is not None:
        try:
            max_finding_severity = Severity(str(maximum).lower())
        except ValueError as exc:
            raise ValueError(
                f"Invalid severity at {location}.max-finding-severity: {maximum}"
            ) from exc

    return PolicyRules(
        require_spec_valid=require_spec_valid,
        max_finding_severity=max_finding_severity,
        denied_capabilities=_string_list(value, "denied-capabilities", location) or (),
        allowed_services=_string_list(value, "allowed-services", location),
        allowed_agent_tools=_string_list(value, "allowed-agent-tools", location),
        exception_expiry_warning_days=_optional_int(
            value, "exception-expiry-warning-days", location, minimum=0
        ),
        max_exception_days=_optional_int(value, "max-exception-days", location, minimum=1),
        require_exception_ticket=require_exception_ticket,
        require_separation_of_duties=require_separation_of_duties,
        capability_exceptions=_exception_list(
            value, "capability-exceptions", location, schema_version
        ),
        service_exceptions=_exception_list(
            value, "service-exceptions", location, schema_version
        ),
        agent_tool_exceptions=_exception_list(
            value, "agent-tool-exceptions", location, schema_version
        ),
    )


def _optional_bool(value: dict[str, Any], key: str, location: str) -> bool | None:
    item = value.get(key)
    if item is not None and not isinstance(item, bool):
        raise ValueError(f"{location}.{key} must be true or false.")
    return item


def _optional_int(
    value: dict[str, Any],
    key: str,
    location: str,
    *,
    minimum: int,
) -> int | None:
    item = value.get(key)
    if item is None:
        return None
    if isinstance(item, bool) or not isinstance(item, int) or item < minimum:
        raise ValueError(f"{location}.{key} must be an integer >= {minimum}.")
    return item


def _string_list(value: dict[str, Any], key: str, location: str) -> tuple[str, ...] | None:
    if key not in value:
        return None
    items = value[key]
    if not isinstance(items, list) or any(
        not isinstance(item, str) or not item for item in items
    ):
        raise ValueError(f"{location}.{key} must be a list of non-empty strings.")
    return tuple(dict.fromkeys(items))


def _exception_list(
    value: dict[str, Any],
    key: str,
    location: str,
    schema_version: str,
) -> tuple[ExceptionGrant, ...]:
    if key not in value:
        return ()
    items = value[key]
    if not isinstance(items, list):
        raise ValueError(f"{location}.{key} must be a list.")

    grants: list[ExceptionGrant] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        item_location = f"{location}.{key}[{index}]"
        if isinstance(item, str):
            if not item:
                raise ValueError(f"{item_location} must not be empty.")
            if schema_version != "1":
                raise ValueError(
                    f"{item_location} must be an exception grant mapping in schema version 2."
                )
            grant = ExceptionGrant(item, "", "", "", None, None, legacy=True)
        elif isinstance(item, dict):
            grant = _parse_exception_grant(item, item_location)
        else:
            raise ValueError(f"{item_location} must be a string or mapping.")

        normalized = grant.item.casefold()
        if normalized in seen:
            raise ValueError(f"Duplicate exception item at {item_location}: {grant.item}")
        seen.add(normalized)
        grants.append(grant)
    return tuple(grants)


def _parse_exception_grant(value: dict[str, Any], location: str) -> ExceptionGrant:
    allowed = {
        "item",
        "reason",
        "owner",
        "approved-by",
        "approved-at",
        "expires-at",
        "ticket",
    }
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(
            f"Unknown exception keys in {location}: {', '.join(sorted(unknown))}"
        )

    required = {
        "item",
        "reason",
        "owner",
        "approved-by",
        "approved-at",
        "expires-at",
    }
    missing = required - set(value)
    if missing:
        raise ValueError(
            f"Missing exception keys in {location}: {', '.join(sorted(missing))}"
        )

    strings: dict[str, str] = {}
    for key in ("item", "reason", "owner", "approved-by"):
        item = value[key]
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{location}.{key} must be a non-empty string.")
        strings[key] = item.strip()

    ticket = value.get("ticket")
    if ticket is not None and (not isinstance(ticket, str) or not ticket.strip()):
        raise ValueError(f"{location}.ticket must be a non-empty string when provided.")

    approved_at = _parse_date(value["approved-at"], f"{location}.approved-at")
    expires_at = _parse_date(value["expires-at"], f"{location}.expires-at")
    if expires_at < approved_at:
        raise ValueError(f"{location}.expires-at must be on or after approved-at.")

    return ExceptionGrant(
        item=strings["item"],
        reason=strings["reason"],
        owner=strings["owner"],
        approved_by=strings["approved-by"],
        approved_at=approved_at,
        expires_at=expires_at,
        ticket=ticket.strip() if isinstance(ticket, str) else None,
    )


def _parse_date(value: Any, location: str) -> date:
    if isinstance(value, datetime):
        raise ValueError(f"{location} must be an ISO date without a time component.")
    if isinstance(value, date):
        return value
    if not isinstance(value, str):
        raise ValueError(f"{location} must be an ISO date in YYYY-MM-DD format.")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{location} must be an ISO date in YYYY-MM-DD format.") from exc


def _merge_rules(defaults: PolicyRules, override: PolicyRules | None) -> PolicyRules:
    override = override or PolicyRules()
    return PolicyRules(
        require_spec_valid=_coalesce_bool(
            override.require_spec_valid, defaults.require_spec_valid, True
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
        exception_expiry_warning_days=_coalesce_int(
            override.exception_expiry_warning_days,
            defaults.exception_expiry_warning_days,
            14,
        ),
        max_exception_days=_coalesce_int(
            override.max_exception_days, defaults.max_exception_days, 90
        ),
        require_exception_ticket=_coalesce_bool(
            override.require_exception_ticket,
            defaults.require_exception_ticket,
            True,
        ),
        require_separation_of_duties=_coalesce_bool(
            override.require_separation_of_duties,
            defaults.require_separation_of_duties,
            True,
        ),
        capability_exceptions=_unique_grants(
            (*defaults.capability_exceptions, *override.capability_exceptions)
        ),
        service_exceptions=_unique_grants(
            (*defaults.service_exceptions, *override.service_exceptions)
        ),
        agent_tool_exceptions=_unique_grants(
            (*defaults.agent_tool_exceptions, *override.agent_tool_exceptions)
        ),
    )


def _coalesce_bool(first: bool | None, second: bool | None, fallback: bool) -> bool:
    if first is not None:
        return first
    if second is not None:
        return second
    return fallback


def _coalesce_int(first: int | None, second: int | None, fallback: int) -> int:
    if first is not None:
        return first
    if second is not None:
        return second
    return fallback


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatchcase(value.casefold(), pattern.casefold()) for pattern in patterns)


def _unique(items: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))


def _unique_grants(items: tuple[ExceptionGrant, ...]) -> tuple[ExceptionGrant, ...]:
    unique: dict[str, ExceptionGrant] = {}
    for item in items:
        unique[item.item.casefold()] = item
    return tuple(unique.values())
