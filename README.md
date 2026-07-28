# SkillBOM

**An evidence-backed bill of materials and capability-drift gate for Agent Skills.**

[![CI](https://github.com/ORANGINGS/skillbom/actions/workflows/ci.yml/badge.svg)](https://github.com/ORANGINGS/skillbom/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Agent Skills can contain instructions, scripts, references, external services, and tool permissions. Traditional package SBOMs do not explain the operational powers that a skill gains over time. SkillBOM statically inspects a skill, records its files and dependencies, infers capabilities, and blocks unexpected privilege drift in pull requests.

> SkillBOM never executes target scripts. Static analysis is best-effort and a clean report is not a security guarantee.

繁體中文說明請見 [README.zh-TW.md](README.zh-TW.md).

## Standards

SkillBOM follows the open Agent Skills specification at `agentskills.io/specification` and supports the project skill layouts documented by GitHub Copilot. It deliberately separates observed capability evidence from malicious-intent judgments.

## Why this project

A code review may clearly show that ten lines changed while hiding the consequential change: a documentation-only skill now reads an API token, calls a new domain, or runs a shell command. SkillBOM makes that change explicit.

```text
Before                          After
filesystem-read                 filesystem-read
                                + credential-access   HIGH
                                + network-access      HIGH
                                + service:api.example.com
```

## Features

- Validates the core open Agent Skills specification (`name`, `description`, metadata, file references).
- Infers operational capabilities with exact file/line evidence.
- Inventories Python imports, Node packages, system tools, agent tools, and external service domains.
- Generates a deterministic, reviewable `skillbom.lock.json` with file hashes.
- Detects new capabilities and dependency drift between two revisions.
- Enforces version-controlled least-privilege policies in CI.
- Emits SARIF for GitHub Code Scanning.
- Works offline and never executes skill code.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .

skillbom scan examples/safe-skill
skillbom scan examples/risky-skill --fail-on high
```

Example finding:

```text
CRITICAL  SHELL-PIPE-001  scripts/install.sh:4
Remote content piped to shell: downloaded content is executed without an integrity check.
```

## Create and compare a baseline

```bash
skillbom lock .github/skills --output skillbom.lock.json

# On a later revision
skillbom lock .github/skills --output /tmp/current.json
skillbom diff skillbom.lock.json /tmp/current.json --fail-on high
```

New capabilities are high-severity drift by default. New service domains and agent tools are medium-severity; content-only changes remain informational.

## Policy-as-code supply-chain gate

Create a least-privilege policy template:

```bash
skillbom init-policy
```

A policy can deny sensitive capabilities, require valid Skill metadata, cap accepted finding severity, and allowlist external services or Agent tools. Schema version 2 makes every exception a time-bounded, reviewable grant:

```yaml
schema-version: "2"
defaults:
  require-spec-valid: true
  max-finding-severity: medium
  denied-capabilities:
    - credential-access
    - privileged-operation
    - destructive-filesystem
  allowed-services:
    - github.com
    - "*.github.com"
  allowed-agent-tools:
    - Read
    - Grep
  exception-expiry-warning-days: 14
  max-exception-days: 90
  require-exception-ticket: true
  require-separation-of-duties: true

skills:
  release-helper:
    capability-exceptions:
      - item: process-execution
        reason: Required to invoke the approved release CLI.
        owner: platform-team
        approved-by: security-team
        approved-at: 2026-07-28
        expires-at: 2026-10-26
        ticket: SEC-123
```

Exception grants are valid through `expires-at`. The gate reports and invalidates expired, future-approved, overlong, self-approved, ticketless, and legacy string exceptions. It also reports unused grants and policy entries for skills that no longer exist, making stale privilege visible during review.

Enforce it locally or in CI:

```bash
skillbom gate .github/skills --policy skillbom.policy.yml
skillbom gate .github/skills --policy skillbom.policy.yml \
  --format sarif --output skillbom-policy.sarif

# Reproduce an audit for a specific date
skillbom gate .github/skills --policy skillbom.policy.yml --as-of 2026-07-28
```

The command exits with code `2` when a violation reaches `--fail-on` (high by default). Policy files are validated strictly so a misspelled security key or incomplete grant fails closed instead of being ignored. Schema version 1 remains readable for migration, but its unaudited string exceptions are rejected by the gate.

## Output formats

```bash
skillbom scan ./skills --format text
skillbom scan ./skills --format json --output report.json
skillbom scan ./skills --format sarif --output skillbom.sarif
```

## Detected capability families

| Capability | Representative evidence |
|---|---|
| `network-access` | `requests`, `fetch`, `curl`, `wget`, sockets |
| `credential-access` | token/secret environment variables, `.ssh`, `.aws`, keyrings |
| `process-execution` | `subprocess`, child processes, shell execution |
| `filesystem-write` | write-mode file operations, redirects, `tee` |
| `package-install` | pip/npm/apt/brew installation |
| `privileged-operation` | `sudo`, broad chmod/chown |
| `destructive-filesystem` | recursive deletion |
| `destructive-vcs` | hard reset, clean, force push |
| `context-influence` | instruction override or concealment language |

## GitHub Actions

The included `capability-drift.yml` loads the trusted lockfile from the PR base branch instead of trusting a modified lockfile in the pull request. The included `action.yml` can also perform a standalone scan.

```yaml
- uses: ORANGINGS/SkillBOM@v0.3.0
  with:
    target: .github/skills
    policy: skillbom.policy.yml
    fail-on: high
    sarif-output: skillbom.sarif
    # as-of: 2026-07-28  # optional reproducible audit date
```

Upload the result with `github/codeql-action/upload-sarif` to receive inline annotations.

## Project structure

```text
src/skillbom/             CLI, parser, scanners, manifest and drift engine
tests/                    Unit tests
examples/                 Safe and intentionally risky sample skills
.github/skills/            A real review skill used to dogfood SkillBOM
.github/workflows/         CI, SARIF and capability-drift gates
docs/architecture.md      Design overview
```

## Scope and limitations

SkillBOM is a portfolio-grade alpha, not a malware verdict engine. It uses deterministic static rules, which means obfuscated, generated, or semantically malicious content may evade detection, while legitimate administrative skills may produce expected warnings. The correct workflow is evidence-backed review, not blind trust in a score.

## Roadmap

- Signed provenance and publisher identity verification.
- Native CycloneDX extension for Agent Skill dependencies.
- Cross-skill trigger collision analysis.
- Archive acquisition protections and signed provenance attestations.
- Optional semantic analysis behind an explicit model provider interface.

## License

MIT
