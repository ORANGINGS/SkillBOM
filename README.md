# SkillBOM

**A zero-key security supply-chain scanner for Agent Skills, MCP servers, and AI tool integrations.**

[![CI](https://github.com/ORANGINGS/SkillBOM/actions/workflows/ci.yml/badge.svg)](https://github.com/ORANGINGS/SkillBOM/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SkillBOM is not a general-purpose bug scanner. It focuses on evidence-backed detection of undeclared or high-risk behavior in AI agent projects:

- shell and subprocess execution
- credential, SSH, environment, and browser-session access
- external network destinations
- dynamic code execution
- package install hooks and remote download-and-execute chains
- exposed MCP tools with high-impact capabilities
- differences between documented behavior and observed code
- capability drift between repository versions

The core scanner is deterministic and does not require a paid AI API key. Public repositories are acquired with a shallow non-interactive `git clone`; local directories are scanned directly.

Traditional Chinese documentation: [README.zh-TW.md](README.zh-TW.md).

## Scan an MCP or Agent repository

```bash
skillbom scan ./my-mcp-server
skillbom scan https://github.com/owner/repository
skillbom scan https://github.com/owner/repository --ref v1.4.0
```

SkillBOM automatically distinguishes a standalone Skill collection from an Agent/MCP repository. Override this when necessary:

```bash
skillbom scan ./project --mode repository
skillbom scan ./skill --mode skill
```

## Compare capability drift

```bash
skillbom repo-diff https://github.com/owner/repository \
  --base-ref v1.3.0 \
  --head-ref v1.4.0
```

The comparison reports newly added capabilities, external services, exposed MCP tools, project classifications, and new high/critical findings. High-severity drift exits with code `2` by default for CI enforcement.

## Repository security checks

- Node.js `preinstall`, `install`, and `postinstall` hooks
- remote content downloaded and piped into a shell
- Node.js `child_process.exec`, `spawn`, and related APIs
- Python subprocess and shell execution through existing static rules
- JavaScript `eval` and `Function`
- `.ssh`, cloud credential files, `.env`, browser Cookies and Login Data
- Python and JavaScript/TypeScript MCP tool registrations
- high-impact behavior located in files that expose MCP tools
- capabilities and service domains missing from README, SKILL.md, SECURITY.md, or `docs/*.md`

Reports are available as text, JSON, and SARIF:

```bash
skillbom scan ./server --format json --output report.json
skillbom scan ./server --format sarif --output report.sarif
```

## Safe public repository acquisition

For GitHub URLs, SkillBOM:

- accepts only public `https://github.com/owner/repository` URLs
- rejects embedded credentials, ports, query parameters, fragments, and nested paths
- uses a shallow, non-interactive clone
- disables repository hooks
- does not initialize submodules
- ignores symbolic links
- enforces repository file and byte limits
- deletes the temporary checkout after analysis

## Agent Skill policy gate

The original Policy-as-Code workflow remains available:

```bash
skillbom init-policy
skillbom gate .github/skills --policy skillbom.policy.yml
```

It enforces least-privilege capabilities, service and Agent-tool allowlists, specification validity, finding thresholds, and time-bounded exception grants with ticketing, separation of duties, and expiry.

## Existing Skill inventory and drift

```bash
skillbom lock .github/skills --output skillbom.lock.json
skillbom diff skillbom.lock.json current.json --fail-on high
```

## Scope and limitations

SkillBOM performs static analysis and never imports or executes target code. A clean report does not prove that a project is safe. The intended claim is narrower:

> Based on visible code, metadata, documentation, and configured rules, SkillBOM identifies known supply-chain risks, undeclared capabilities, and capability drift.

Dependency vulnerability intelligence, deeper taint analysis, sandbox execution, and signed publisher provenance are separate roadmap layers.

See [repository scanning documentation](docs/repository-scanning.md) for details.

## License

MIT
