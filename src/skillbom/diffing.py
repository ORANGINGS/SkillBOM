from __future__ import annotations

from typing import Any

from skillbom.models import Drift, Severity


def compare_manifests(old: dict[str, Any], new: dict[str, Any]) -> list[Drift]:
    drifts: list[Drift] = []
    old_skills = {item["name"]: item for item in old.get("skills", [])}
    new_skills = {item["name"]: item for item in new.get("skills", [])}

    for skill_name in sorted(new_skills.keys() - old_skills.keys()):
        drifts.append(
            Drift("skill-added", Severity.MEDIUM, skill_name, skill_name, "A new skill was added.")
        )
    for skill_name in sorted(old_skills.keys() - new_skills.keys()):
        drifts.append(
            Drift("skill-removed", Severity.LOW, skill_name, skill_name, "A skill was removed.")
        )

    for skill_name in sorted(old_skills.keys() & new_skills.keys()):
        old_skill = old_skills[skill_name]
        new_skill = new_skills[skill_name]

        old_caps = {item["name"] for item in old_skill.get("capabilities", [])}
        new_caps = {item["name"] for item in new_skill.get("capabilities", [])}
        for capability in sorted(new_caps - old_caps):
            drifts.append(
                Drift(
                    "capability-added",
                    Severity.HIGH,
                    skill_name,
                    capability,
                    f"Skill gained capability '{capability}'.",
                )
            )
        for capability in sorted(old_caps - new_caps):
            drifts.append(
                Drift(
                    "capability-removed",
                    Severity.INFO,
                    skill_name,
                    capability,
                    f"Skill no longer declares/inherits capability '{capability}'.",
                )
            )

        old_deps = {(item["kind"], item["name"]) for item in old_skill.get("dependencies", [])}
        new_deps = {(item["kind"], item["name"]) for item in new_skill.get("dependencies", [])}
        for kind, name in sorted(new_deps - old_deps):
            severity = Severity.MEDIUM if kind in {"service", "agent-tool"} else Severity.LOW
            drifts.append(
                Drift(
                    "dependency-added",
                    severity,
                    skill_name,
                    f"{kind}:{name}",
                    f"Skill gained dependency '{kind}:{name}'.",
                )
            )
        for kind, name in sorted(old_deps - new_deps):
            drifts.append(
                Drift(
                    "dependency-removed",
                    Severity.INFO,
                    skill_name,
                    f"{kind}:{name}",
                    f"Skill removed dependency '{kind}:{name}'.",
                )
            )

        old_findings = {(item["rule_id"], item["evidence"]["file"]) for item in old_skill.get("findings", [])}
        for item in new_skill.get("findings", []):
            key = (item["rule_id"], item["evidence"]["file"])
            if key not in old_findings and item["severity"] in {"high", "critical"}:
                drifts.append(
                    Drift(
                        "high-finding-added",
                        Severity(item["severity"]),
                        skill_name,
                        item["rule_id"],
                        f"New {item['severity']} finding {item['rule_id']}: {item['title']}",
                    )
                )

        if old_skill.get("digest") != new_skill.get("digest"):
            drifts.append(
                Drift(
                    "content-changed",
                    Severity.INFO,
                    skill_name,
                    "digest",
                    "Skill content digest changed.",
                )
            )

    return sorted(drifts, key=lambda item: (-item.severity.rank, item.skill, item.kind, item.item))
