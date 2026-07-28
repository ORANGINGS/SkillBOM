# Repository security scanning

SkillBOM 0.4 extends the original Agent Skill scanner to whole repositories that contain MCP servers, Agent Skills, or AI tool integrations. The core scanner is deterministic and does not require an AI API key.

## Public GitHub repositories

```bash
skillbom scan https://github.com/owner/repository
skillbom scan https://github.com/owner/repository --ref v1.4.0
```

SkillBOM accepts only public `https://github.com/owner/repository` URLs. It performs a shallow, non-interactive clone, does not initialize submodules, disables repository hooks, enforces file and byte limits, ignores symbolic links, and deletes the temporary checkout after the report is generated.

Local repositories are also supported:

```bash
skillbom scan ./my-mcp-server --mode repository
```

The existing Skill behavior remains available:

```bash
skillbom scan .github/skills
skillbom scan ./my-skill --mode skill
```

## Project-level findings

Repository mode combines the existing static rules with project-specific checks:

- Detects MCP servers through package dependencies, Python imports, and MCP registration APIs.
- Inventories exposed Python and JavaScript/TypeScript MCP tools.
- Detects Node.js `preinstall`, `install`, and `postinstall` hooks.
- Raises a critical finding when an install hook downloads and executes remote content.
- Detects Node.js child-process execution and dynamic JavaScript evaluation.
- Detects references to SSH keys, cloud credentials, `.env` files, and browser session stores.
- Correlates exposed MCP tools with high-impact behavior in the same source file.
- Reports capabilities and external domains observed in code but not disclosed in README, SKILL.md, or `docs/*.md`.

Reports are available as terminal output, JSON, or SARIF:

```bash
skillbom scan ./server --format json --output report.json
skillbom scan ./server --format sarif --output report.sarif
```

## Capability drift between releases

```bash
skillbom repo-diff https://github.com/owner/repository \
  --base-ref v1.3.0 \
  --head-ref v1.4.0
```

The drift report highlights newly added capabilities, external services, exposed MCP tools, and new high/critical findings. A high-severity drift exits with code `2` by default so it can block CI.

The same comparison can be performed from saved JSON reports:

```bash
skillbom scan https://github.com/owner/repository --ref v1.3.0 --format json -o old.json
skillbom scan https://github.com/owner/repository --ref v1.4.0 --format json -o new.json
skillbom diff old.json new.json
```

## Current boundaries

The scanner does not execute repository code and does not claim that a clean report proves safety. Dependency vulnerability lookup, deeper taint analysis, sandbox execution, and signed publisher provenance are separate layers on the roadmap.
