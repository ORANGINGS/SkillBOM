# Changelog

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
