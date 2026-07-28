from pathlib import Path

from skillbom.manifest import build_manifest


def write_skill(root: Path, content: str) -> None:
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text(content, encoding="utf-8")


def test_valid_skill(tmp_path: Path) -> None:
    skill = tmp_path / "data-review"
    write_skill(
        skill,
        """---
name: data-review
description: Reviews CSV quality. Use when the user asks to validate tabular data.
metadata:
  version: "0.1.0"
---
# Workflow
1. Read the data.
2. Report missing values.
""",
    )
    manifest = build_manifest(skill)
    record = manifest.skills[0]
    assert record.spec_valid is True
    assert record.name == "data-review"
    assert not any(item.rule_id.startswith("SPEC-") for item in record.findings)


def test_invalid_name_and_missing_description(tmp_path: Path) -> None:
    skill = tmp_path / "bad-skill"
    write_skill(skill, "---\nname: Bad_Skill\n---\nDo work.\n")
    record = build_manifest(skill).skills[0]
    rule_ids = {item.rule_id for item in record.findings}
    assert "SPEC-003" in rule_ids
    assert "SPEC-004" in rule_ids
    assert "SPEC-005" in rule_ids
    assert record.spec_valid is False


def test_lock_manifest_is_deterministic(tmp_path: Path) -> None:
    skill = tmp_path / "stable-skill"
    write_skill(
        skill,
        """---
name: stable-skill
description: Reads a local file. Use when the user asks to inspect local text.
---
# Workflow
Read the requested file.
""",
    )
    first = build_manifest(skill, include_timestamp=False).to_dict()
    second = build_manifest(skill, include_timestamp=False).to_dict()
    assert first == second
    assert first["generated_at"] is None
