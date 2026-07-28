from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from skillbom import __version__
from skillbom.models import FileRecord, Manifest, Severity, SkillRecord
from skillbom.parser import discover_skills, parse_skill
from skillbom.scanners import is_spec_valid, scan_dependencies, scan_security, scan_spec
from skillbom.utils import iter_files, relative, sha256_file

DEDUCTIONS = {
    Severity.INFO: 0,
    Severity.LOW: 3,
    Severity.MEDIUM: 8,
    Severity.HIGH: 18,
    Severity.CRITICAL: 35,
}


def build_manifest(target: Path, *, include_timestamp: bool = True) -> Manifest:
    display_target = target.as_posix()
    target = target.resolve()
    skill_roots = discover_skills(target)
    if not skill_roots:
        raise ValueError(f"No SKILL.md found under {target}")

    skills = [build_skill_record(root, target) for root in skill_roots]
    return Manifest(
        schema_version="0.1",
        generated_at=datetime.now(timezone.utc).isoformat() if include_timestamp else None,
        target=display_target,
        tool={"name": "skillbom", "version": __version__},
        skills=skills,
    )


def build_skill_record(root: Path, target: Path) -> SkillRecord:
    parsed = parse_skill(root)
    spec_findings = scan_spec(parsed)
    security_findings, capabilities = scan_security(root)
    findings = sorted(
        [*spec_findings, *security_findings],
        key=lambda item: (-item.severity.rank, item.rule_id, item.evidence.file, item.evidence.line),
    )
    dependencies = scan_dependencies(root, parsed.metadata)
    files = [
        FileRecord(relative(path, root), sha256_file(path), path.stat().st_size)
        for path in iter_files(root)
    ]
    digest_input = json.dumps(
        [{"path": item.path, "sha256": item.sha256} for item in files],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(digest_input).hexdigest()
    score = max(0, 100 - sum(DEDUCTIONS[item.severity] for item in findings))
    name = parsed.metadata.get("name")
    skill_name = name if isinstance(name, str) and name else root.name
    return SkillRecord(
        name=skill_name,
        path=relative(root, target),
        metadata=parsed.metadata,
        spec_valid=is_spec_valid(findings),
        score=score,
        capabilities=capabilities,
        dependencies=dependencies,
        findings=findings,
        files=files,
        digest=digest,
    )


def write_manifest(manifest: Manifest, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def read_manifest(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))
