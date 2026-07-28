# Contributing

1. Create a focused branch.
2. Add or update tests for every rule change.
3. Run `ruff check .` and `pytest`.
4. Explain false-positive and false-negative trade-offs in the pull request.

Detection rules must include a stable rule ID, severity, evidence location, and remediation. Avoid rules that label a capability as malicious by itself; capability evidence and risk findings are separate concepts.
