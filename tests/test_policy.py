from datetime import date
from pathlib import Path

import pytest

from skillbom.manifest import build_manifest
from skillbom.policy import default_policy_text, evaluate_policy, read_policy


def write_skill(root: Path, *, script: str, metadata: str = "") -> None:
    (root / "scripts").mkdir(parents=True)
    (root / "SKILL.md").write_text(
        f"""---
name: {root.name}
description: Runs a controlled workflow. Use when the user requests this test.
{metadata}---
# Workflow
Run the script.
""",
        encoding="utf-8",
    )
    (root / "scripts" / "run.py").write_text(script, encoding="utf-8")


def write_policy(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def governed_exception(item: str, *, expires_at: str = "2026-08-31", ticket: str = "SEC-1") -> str:
    ticket_line = f"        ticket: {ticket}\n" if ticket else ""
    return (
        f"      - item: {item}\n"
        "        reason: Required by the approved test workflow.\n"
        "        owner: platform-team\n"
        "        approved-by: security-team\n"
        "        approved-at: 2026-07-01\n"
        f"        expires-at: {expires_at}\n"
        f"{ticket_line}"
    )


def test_denied_capability_blocks_skill(tmp_path: Path) -> None:
    skill = tmp_path / "uploader"
    write_skill(skill, script="import os\nprint(os.getenv('API_TOKEN'))\n")
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        'schema-version: "2"\ndefaults:\n  denied-capabilities: [credential-access]\n',
    )
    violations = evaluate_policy(
        build_manifest(skill), read_policy(policy_path), as_of=date(2026, 7, 28)
    )
    assert any(item.rule_id == "POLICY-CAPABILITY-001" for item in violations)


def test_governed_capability_exception_allows_denied_capability(tmp_path: Path) -> None:
    skill = tmp_path / "uploader"
    write_skill(skill, script="import os\nprint(os.getenv('API_TOKEN'))\n")
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        'schema-version: "2"\n'
        "defaults:\n"
        "  denied-capabilities: [credential-access]\n"
        "skills:\n"
        "  uploader:\n"
        "    capability-exceptions:\n"
        + governed_exception("credential-access"),
    )
    violations = evaluate_policy(
        build_manifest(skill), read_policy(policy_path), as_of=date(2026, 7, 28)
    )
    assert not any(item.rule_id == "POLICY-CAPABILITY-001" for item in violations)
    assert not any(item.severity.value == "high" for item in violations)


def test_expired_exception_blocks_and_reports_expiry(tmp_path: Path) -> None:
    skill = tmp_path / "uploader"
    write_skill(skill, script="import os\nprint(os.getenv('API_TOKEN'))\n")
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        'schema-version: "2"\n'
        "defaults:\n"
        "  denied-capabilities: [credential-access]\n"
        "skills:\n"
        "  uploader:\n"
        "    capability-exceptions:\n"
        + governed_exception("credential-access", expires_at="2026-07-27"),
    )
    violations = evaluate_policy(
        build_manifest(skill), read_policy(policy_path), as_of=date(2026, 7, 28)
    )
    assert any(item.rule_id == "POLICY-EXCEPTION-EXPIRED-001" for item in violations)


def test_exception_expiry_date_is_inclusive(tmp_path: Path) -> None:
    skill = tmp_path / "uploader"
    write_skill(skill, script="import os\nprint(os.getenv('API_TOKEN'))\n")
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        'schema-version: "2"\n'
        "defaults:\n"
        "  denied-capabilities: [credential-access]\n"
        "skills:\n"
        "  uploader:\n"
        "    capability-exceptions:\n"
        + governed_exception("credential-access", expires_at="2026-07-28"),
    )
    violations = evaluate_policy(
        build_manifest(skill), read_policy(policy_path), as_of=date(2026, 7, 28)
    )
    assert not any(item.rule_id == "POLICY-EXCEPTION-EXPIRED-001" for item in violations)
    assert any(item.rule_id == "POLICY-EXCEPTION-EXPIRING-001" for item in violations)


def test_missing_ticket_invalidates_exception(tmp_path: Path) -> None:
    skill = tmp_path / "uploader"
    write_skill(skill, script="import os\nprint(os.getenv('API_TOKEN'))\n")
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        'schema-version: "2"\n'
        "defaults:\n"
        "  denied-capabilities: [credential-access]\n"
        "  require-exception-ticket: true\n"
        "skills:\n"
        "  uploader:\n"
        "    capability-exceptions:\n"
        + governed_exception("credential-access", ticket=""),
    )
    violations = evaluate_policy(
        build_manifest(skill), read_policy(policy_path), as_of=date(2026, 7, 28)
    )
    assert any(item.rule_id == "POLICY-EXCEPTION-TICKET-001" for item in violations)


def test_self_approval_invalidates_exception(tmp_path: Path) -> None:
    skill = tmp_path / "uploader"
    write_skill(skill, script="import os\nprint(os.getenv('API_TOKEN'))\n")
    policy_path = tmp_path / "policy.yml"
    text = (
        'schema-version: "2"\n'
        "defaults:\n"
        "  denied-capabilities: [credential-access]\n"
        "skills:\n"
        "  uploader:\n"
        "    capability-exceptions:\n"
        + governed_exception("credential-access")
    ).replace("approved-by: security-team", "approved-by: platform-team")
    write_policy(policy_path, text)
    violations = evaluate_policy(
        build_manifest(skill), read_policy(policy_path), as_of=date(2026, 7, 28)
    )
    assert any(item.rule_id == "POLICY-EXCEPTION-SEPARATION-001" for item in violations)


def test_exception_duration_limit_is_enforced(tmp_path: Path) -> None:
    skill = tmp_path / "uploader"
    write_skill(skill, script="import os\nprint(os.getenv('API_TOKEN'))\n")
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        'schema-version: "2"\n'
        "defaults:\n"
        "  denied-capabilities: [credential-access]\n"
        "  max-exception-days: 30\n"
        "skills:\n"
        "  uploader:\n"
        "    capability-exceptions:\n"
        + governed_exception("credential-access", expires_at="2026-09-30"),
    )
    violations = evaluate_policy(
        build_manifest(skill), read_policy(policy_path), as_of=date(2026, 7, 28)
    )
    assert any(item.rule_id == "POLICY-EXCEPTION-DURATION-001" for item in violations)


def test_unused_exception_is_reported(tmp_path: Path) -> None:
    skill = tmp_path / "reader"
    write_skill(skill, script="print('local only')\n")
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        'schema-version: "2"\n'
        "defaults:\n"
        "  denied-capabilities: [credential-access]\n"
        "skills:\n"
        "  reader:\n"
        "    capability-exceptions:\n"
        + governed_exception("credential-access"),
    )
    violations = evaluate_policy(
        build_manifest(skill), read_policy(policy_path), as_of=date(2026, 7, 28)
    )
    assert any(item.rule_id == "POLICY-EXCEPTION-UNUSED-001" for item in violations)


def test_unknown_policy_skill_is_reported(tmp_path: Path) -> None:
    skills_root = tmp_path / "skills"
    skill = skills_root / "reader"
    write_skill(skill, script="print('local only')\n")
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        'schema-version: "2"\nskills:\n  removed-skill:\n    require-spec-valid: true\n',
    )
    violations = evaluate_policy(
        build_manifest(skills_root), read_policy(policy_path), as_of=date(2026, 7, 28)
    )
    assert any(item.rule_id == "POLICY-SKILL-UNKNOWN-001" for item in violations)


def test_service_allowlist_supports_wildcards(tmp_path: Path) -> None:
    skill = tmp_path / "client"
    write_skill(
        skill,
        script=(
            "import requests\n"
            "requests.get('https://api.github.com/repos')\n"
            "requests.get('https://evil.example/upload')\n"
        ),
    )
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        'schema-version: "2"\ndefaults:\n  allowed-services: ["*.github.com"]\n',
    )
    violations = evaluate_policy(
        build_manifest(skill), read_policy(policy_path), as_of=date(2026, 7, 28)
    )
    services = {item.subject for item in violations if item.rule_id == "POLICY-SERVICE-001"}
    assert "evil.example" in services
    assert "api.github.com" not in services


def test_maximum_finding_severity_is_enforced(tmp_path: Path) -> None:
    skill = tmp_path / "installer"
    write_skill(skill, script="import os\nos.system('echo unsafe')\n")
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        'schema-version: "2"\ndefaults:\n  max-finding-severity: medium\n',
    )
    violations = evaluate_policy(
        build_manifest(skill), read_policy(policy_path), as_of=date(2026, 7, 28)
    )
    assert any(item.subject == "PY-OS-001" for item in violations)


def test_schema_v2_rejects_string_exception(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        'schema-version: "2"\nskills:\n  uploader:\n    capability-exceptions: [credential-access]\n',
    )
    with pytest.raises(ValueError, match="exception grant mapping"):
        read_policy(policy_path)


def test_schema_v1_legacy_exception_is_fail_closed(tmp_path: Path) -> None:
    skill = tmp_path / "uploader"
    write_skill(skill, script="import os\nprint(os.getenv('API_TOKEN'))\n")
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        'schema-version: "1"\ndefaults:\n  denied-capabilities: [credential-access]\nskills:\n  uploader:\n    capability-exceptions: [credential-access]\n',
    )
    violations = evaluate_policy(
        build_manifest(skill), read_policy(policy_path), as_of=date(2026, 7, 28)
    )
    assert any(item.rule_id == "POLICY-EXCEPTION-LEGACY-001" for item in violations)


def test_schema_v2_rejects_global_exceptions(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        'schema-version: "2"\ndefaults:\n  capability-exceptions: []\n',
    )
    with pytest.raises(ValueError, match="must be scoped"):
        read_policy(policy_path)


def test_unknown_policy_key_is_rejected(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yml"
    write_policy(policy_path, "defaults:\n  allow-serivces: [example.com]\n")
    with pytest.raises(ValueError, match="Unknown keys"):
        read_policy(policy_path)


def test_default_policy_uses_fresh_governed_grant() -> None:
    text = default_policy_text(as_of=date(2026, 7, 28))
    assert 'schema-version: "2"' in text
    assert "approved-at: 2026-07-28" in text
    assert "expires-at: 2026-10-26" in text
