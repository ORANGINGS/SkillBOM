# Architecture

SkillBOM is an offline static-analysis and policy-enforcement pipeline:

```text
Skill directories
      |
      v
Discovery -> SKILL.md parser -> Spec checks
      |              |              |
      |              v              v
      +--------> File scanner -> Findings + capabilities
                     |
                     v
              Dependency inventory
                     |
          +----------+-----------+
          |                      |
          v                      v
 skillbom.lock.json      skillbom.policy.yml
          |                      |
          v                      v
 Capability drift       Policy-as-code gate
          |                      |
          +----------+-----------+
                     |
                     v
             Text / JSON / SARIF
```

The scanner never imports or executes code from the target skill. Findings retain file, line, and snippet evidence. Capabilities describe what a skill appears able to do; they do not by themselves imply malicious intent.

The policy engine is deterministic and deny-by-rule. It can require specification compliance, cap accepted finding severity, deny sensitive capabilities, and allowlist external domains or Agent tools. Skill-specific exceptions are explicit in version-controlled YAML so reviewers can see policy changes in the same pull request as code changes.
