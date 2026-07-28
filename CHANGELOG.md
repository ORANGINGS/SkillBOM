# Changelog

## 0.4.0

- Scan local Agent/MCP projects and public GitHub repository URLs without a paid API key.
- Classify Agent Skill, MCP Server, Agent integration, and generic AI tool repositories.
- Inventory exposed Python and JavaScript/TypeScript MCP tools.
- Detect Node install hooks, remote download-and-execute behavior, child processes, dynamic evaluation, and sensitive credential/browser paths.
- Report capabilities and external domains observed in code but not disclosed in project documentation.
- Add repository-level JSON/SARIF output and Git-ref capability drift through `skillbom repo-diff`.
- Harden public repository acquisition with shallow non-interactive clones, disabled hooks, resource limits, symlink exclusion, and temporary checkout cleanup.

## 0.3.0

- Replace unaudited string exceptions with time-bounded exception grants in policy schema version 2.
- Require reason, owner, independent approver, approval date, expiry date, and optionally a ticket.
- Block expired, future-approved, overlong, self-approved, ticketless, and legacy exceptions.
- Report expiring, unused, and orphaned policy grants to reduce permanent privilege accumulation.
- Add reproducible date-based evaluation through `skillbom gate --as-of YYYY-MM-DD`.

## 0.2.0

- Add a policy-as-code gate with global defaults and per-skill overrides.
- Block denied capabilities, unapproved external services, and unapproved Agent tools.
- Enforce Agent Skills specification validity and a maximum finding severity.
- Support wildcard allowlists, explicit exceptions, JSON output, and SARIF output.
- Add `skillbom init-policy`, a JSON Schema, CI coverage, and policy mode for the composite GitHub Action.

## 0.1.0

- Validate core Agent Skills specification fields.
- Infer network, credential, process, filesystem, package-install, privilege, and destructive capabilities.
- Inventory Python, Node, system-tool, service, and agent-tool dependencies.
- Generate JSON lockfiles and SARIF reports.
- Detect capability and dependency drift between versions.
