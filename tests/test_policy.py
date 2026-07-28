from pathlib import Path

import pytest

from skillbom.manifest import build_manifest
from skillbom.policy import evaluate_policy, read_policy


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


def test_denied_capability_blocks_skill(tmp_path: Path) -> None:
    skill = tmp_path / "uploader"
    write_skill(skill, script="import os\nprint(os.getenv('API_TOKEN'))\n")
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        """schema-version: "1"
defaults:
  denied-capabilities: [credential-access]
""",
    )
    violations = evaluate_policy(build_manifest(skill), read_policy(policy_path))
    assert any(item.rule_id == "POLICY-CAPABILITY-001" for item in violations)


def test_skill_capability_exception_allows_denied_capability(tmp_path: Path) -> None:
    skill = tmp_path / "uploader"
    write_skill(skill, script="import os\nprint(os.getenv('API_TOKEN'))\n")
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        """defaults:
  denied-capabilities: [credential-access]
skills:
  uploader:
    capability-exceptions: [credential-access]
""",
    )
    violations = evaluate_policy(build_manifest(skill), read_policy(policy_path))
    assert not any(item.rule_id == "POLICY-CAPABILITY-001" for item in violations)


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
        """defaults:
  allowed-services: ["*.github.com"]
""",
    )
    violations = evaluate_policy(build_manifest(skill), read_policy(policy_path))
    services = {item.subject for item in violations if item.rule_id == "POLICY-SERVICE-001"}
    assert "evil.example" in services
    assert "api.github.com" not in services


def test_maximum_finding_severity_is_enforced(tmp_path: Path) -> None:
    skill = tmp_path / "installer"
    write_skill(
        skill,
        script="import os\nos.system('echo unsafe')\n",
    )
    policy_path = tmp_path / "policy.yml"
    write_policy(
        policy_path,
        """defaults:
  max-finding-severity: medium
""",
    )
    violations = evaluate_policy(build_manifest(skill), read_policy(policy_path))
    assert any(item.subject == "PY-OS-001" for item in violations)


def test_unknown_policy_key_is_rejected(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yml"
    write_policy(policy_path, "defaults:\n  allow-serivces: [example.com]\n")
    with pytest.raises(ValueError, match="Unknown keys"):
        read_policy(policy_path)
