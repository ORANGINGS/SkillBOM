# Changelog

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
