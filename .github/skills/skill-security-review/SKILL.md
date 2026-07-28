---
name: skill-security-review
description: Reviews changes to Agent Skill files for specification compliance, capability drift, dependency changes, and unsafe scripts. Use when reviewing a pull request that modifies SKILL.md, scripts, references, or assets inside a skill directory.
license: MIT
compatibility: Requires Python 3.11+ and the local SkillBOM package.
metadata:
  version: "0.1.0"
---

# Skill security review

## Workflow

1. Identify every changed skill directory.
2. Run `skillbom scan PATH --format text` for each changed skill.
3. Generate a temporary lockfile with `skillbom lock PATH --output /tmp/current-skillbom.json`.
4. Compare it with the trusted base-branch lockfile using `skillbom diff BASELINE /tmp/current-skillbom.json`.
5. Treat new network, credential, process, package-install, privilege, or destructive capabilities as requiring explicit review.
6. Report exact files and lines, distinguish evidence from inference, and do not execute skill scripts.

## Review standard

- Block critical findings.
- Require justification for high-severity capability drift.
- Confirm that external services and tools are documented in `compatibility` or references.
- Confirm that the skill name matches its directory and the description states both purpose and activation conditions.
