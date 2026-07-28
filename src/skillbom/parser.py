from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

FRONTMATTER_RE = re.compile(r"\A---\s*\n(?P<yaml>.*?)\n---\s*(?:\n|\Z)(?P<body>.*)\Z", re.DOTALL)


@dataclass(slots=True)
class ParsedSkill:
    root: Path
    skill_file: Path
    raw: str
    metadata: dict[str, Any]
    body: str
    body_start_line: int
    parse_error: str | None = None


def discover_skills(target: Path) -> list[Path]:
    target = target.resolve()
    if target.is_file() and target.name == "SKILL.md":
        return [target.parent]
    if (target / "SKILL.md").is_file():
        return [target]
    roots = []
    for skill_file in target.rglob("SKILL.md"):
        if any(part in {".git", ".venv", "venv", "node_modules"} for part in skill_file.parts):
            continue
        roots.append(skill_file.parent)
    return sorted(set(roots))


def parse_skill(root: Path) -> ParsedSkill:
    skill_file = root / "SKILL.md"
    raw = skill_file.read_text(encoding="utf-8")
    match = FRONTMATTER_RE.match(raw)
    if not match:
        return ParsedSkill(
            root=root,
            skill_file=skill_file,
            raw=raw,
            metadata={},
            body=raw,
            body_start_line=1,
            parse_error="SKILL.md must begin with YAML frontmatter delimited by --- lines.",
        )

    yaml_text = match.group("yaml")
    body = match.group("body")
    try:
        loaded = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        return ParsedSkill(
            root=root,
            skill_file=skill_file,
            raw=raw,
            metadata={},
            body=body,
            body_start_line=yaml_text.count("\n") + 4,
            parse_error=f"Invalid YAML frontmatter: {exc}",
        )

    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        return ParsedSkill(
            root=root,
            skill_file=skill_file,
            raw=raw,
            metadata={},
            body=body,
            body_start_line=yaml_text.count("\n") + 4,
            parse_error="YAML frontmatter must be a mapping.",
        )

    return ParsedSkill(
        root=root,
        skill_file=skill_file,
        raw=raw,
        metadata=loaded,
        body=body,
        body_start_line=yaml_text.count("\n") + 4,
    )
