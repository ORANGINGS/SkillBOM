# Architecture

SkillBOM is an offline static-analysis pipeline:

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
                     v
              skillbom.lock.json
                     |
                     v
              Drift comparison / SARIF
```

The scanner never imports or executes code from the target skill. Findings retain file, line, and snippet evidence. Capabilities describe what a skill appears able to do; they do not by themselves imply malicious intent.
