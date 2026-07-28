from __future__ import annotations

import re
from pathlib import Path

from skillbom.models import Evidence, Finding, Severity
from skillbom.utils import clean_snippet, iter_files, read_text, relative


def scan_code_behaviors(root: Path) -> tuple[list[Finding], dict[str, list[Evidence]]]:
    findings: list[Finding] = []
    capabilities: dict[str, list[Evidence]] = {}

    def add(
        rule_id: str,
        title: str,
        message: str,
        remediation: str,
        evidence: Evidence,
        capability: str,
    ) -> None:
        findings.append(
            Finding(rule_id, Severity.HIGH, capability, title, message, evidence, remediation)
        )
        capabilities.setdefault(capability, []).append(evidence)

    for path in iter_files(root):
        if path.is_symlink():
            continue
        text = read_text(path)
        if text is None:
            continue
        rel = relative(path, root)
        for line_number, line in enumerate(text.splitlines(), start=1):
            evidence = Evidence(rel, line_number, clean_snippet(line))
            if path.suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx"}:
                if re.search(
                    r"\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync|execFile|fork)\s*\(",
                    line,
                ):
                    add(
                        "JS-PROCESS-001",
                        "Node.js process execution",
                        "The project can start operating-system processes or commands.",
                        "Use argument arrays, constrain executables, validate inputs, and disclose this capability.",
                        evidence,
                        "process-execution",
                    )
                if re.search(r"\b(?:eval|Function)\s*\(", line):
                    add(
                        "JS-DYNAMIC-001",
                        "Dynamic JavaScript execution",
                        "The project dynamically evaluates JavaScript source.",
                        "Replace dynamic evaluation with explicit parsing or an allowlisted dispatcher.",
                        evidence,
                        "code-execution",
                    )
            if re.search(
                r"(?:\.ssh(?:[/\\]|[\"'])|id_rsa|id_ed25519|\.aws[/\\]credentials|"
                r"(?:^|[/\\])\.env(?:\.|[\"']|$)|"
                r"(?:Chrome|Chromium|Edge|Firefox)[^\n]{0,100}(?:Cookies|Login Data|Local State)|"
                r"(?:Cookies|Login Data)[\"'])",
                line,
                re.IGNORECASE,
            ):
                add(
                    "SENSITIVE-PATH-001",
                    "Sensitive local data path",
                    "The project references credential, SSH, environment, or browser-session data.",
                    "Limit access to documented paths and never transmit contents without explicit approval.",
                    evidence,
                    "credential-access",
                )
    return findings, capabilities
