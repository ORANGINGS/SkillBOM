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

The policy engine is deterministic and deny-by-rule. It can require specification compliance, cap accepted finding severity, deny sensitive capabilities, and allowlist external domains or Agent tools.

Schema version 2 models exceptions as governance records rather than strings. Each grant has a subject, reason, owner, independent approver, approval date, expiry date, and optional ticket. Evaluation is date-aware and fails closed when a grant is expired, not yet valid, longer than policy permits, missing required evidence, self-approved, or inherited from the legacy schema. Low/medium findings also expose unused grants and rules for skills that no longer exist so privileges can be removed instead of accumulating indefinitely.
