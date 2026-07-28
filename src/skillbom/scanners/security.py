from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from skillbom.models import Capability, Evidence, Finding, Severity
from skillbom.utils import clean_snippet, iter_files, read_text, relative


@dataclass(slots=True, frozen=True)
class Rule:
    rule_id: str
    severity: Severity
    category: str
    title: str
    pattern: re.Pattern[str]
    message: str
    remediation: str
    capability: str | None = None


def _rule(
    rule_id: str,
    severity: Severity,
    category: str,
    title: str,
    pattern: str,
    message: str,
    remediation: str,
    capability: str | None = None,
) -> Rule:
    return Rule(
        rule_id,
        severity,
        category,
        title,
        re.compile(pattern, re.IGNORECASE),
        message,
        remediation,
        capability,
    )


RULES = (
    _rule(
        "PY-EXEC-001",
        Severity.HIGH,
        "code-execution",
        "Dynamic Python execution",
        r"\b(?:eval|exec)\s*\(",
        "Dynamic code execution can run attacker-controlled content.",
        "Replace dynamic execution with explicit parsing or a strict allowlist.",
        "code-execution",
    ),
    _rule(
        "PY-SHELL-001",
        Severity.HIGH,
        "process",
        "Shell-enabled subprocess",
        r"\b(?:subprocess\.(?:run|Popen|call|check_call|check_output))\s*\([^\n]*shell\s*=\s*True",
        "shell=True expands command-injection risk.",
        "Pass an argument list and keep shell=False.",
        "process-execution",
    ),
    _rule(
        "PY-OS-001",
        Severity.HIGH,
        "process",
        "os.system execution",
        r"\bos\.system\s*\(",
        "os.system executes a command through the system shell.",
        "Use subprocess.run with an argument list and validated inputs.",
        "process-execution",
    ),
    _rule(
        "SHELL-PIPE-001",
        Severity.CRITICAL,
        "supply-chain",
        "Remote content piped to shell",
        r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|powershell)\b",
        "Downloaded content is executed without an integrity check.",
        "Download to a file, verify a pinned checksum/signature, then execute explicitly.",
        "network-access",
    ),
    _rule(
        "FS-DESTROY-001",
        Severity.HIGH,
        "destructive",
        "Recursive forced deletion",
        r"\brm\s+-[A-Za-z]*r[A-Za-z]*f|\brm\s+-[A-Za-z]*f[A-Za-z]*r|shutil\.rmtree\s*\(",
        "Recursive deletion can remove large amounts of data.",
        "Restrict deletion to a validated workspace path and require confirmation.",
        "destructive-filesystem",
    ),
    _rule(
        "GIT-DESTRUCTIVE-001",
        Severity.HIGH,
        "destructive",
        "Destructive Git operation",
        r"\bgit\s+(?:reset\s+--hard|clean\s+-[a-zA-Z]*f|push\s+[^\n]*--force)\b",
        "The command can discard work or rewrite remote history.",
        "Use non-destructive alternatives and require explicit user approval.",
        "destructive-vcs",
    ),
    _rule(
        "PRIV-001",
        Severity.MEDIUM,
        "privilege",
        "Privilege escalation command",
        r"(?:^|\s)sudo\s+|\bchmod\s+777\b|\bchown\s+-R\b",
        "The skill requests elevated or overly broad filesystem privileges.",
        "Document the need, minimize scope, and avoid world-writable permissions.",
        "privileged-operation",
    ),
    _rule(
        "INSTALL-001",
        Severity.MEDIUM,
        "supply-chain",
        "Runtime package installation",
        r"\b(?:pip(?:3)?\s+install|uv\s+pip\s+install|npm\s+(?:i|install)|pnpm\s+(?:i|install)|yarn\s+add|apt(?:-get)?\s+install|brew\s+install)\b",
        "Installing dependencies at runtime changes the execution environment.",
        "Pin versions and hashes, and document installation as an explicit setup step.",
        "package-install",
    ),
    _rule(
        "NET-001",
        Severity.LOW,
        "network",
        "Network-capable code",
        r"\b(?:requests\.(?:get|post|put|patch|delete|request|Session)|httpx\.(?:get|post|put|patch|delete|request|Client|AsyncClient)|aiohttp\.(?:ClientSession|request)|urllib\.request\.|fetch\s*\(|curl\s+|wget\s+|Invoke-WebRequest|socket\.)",
        "The skill can make outbound network requests.",
        "Declare required domains and explain what data may leave the machine.",
        "network-access",
    ),
    _rule(
        "CRED-001",
        Severity.MEDIUM,
        "credentials",
        "Credential access indicator",
        r"(?:os\.environ|getenv\s*\(|\$\{?[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\}?|~/\.(?:ssh|aws)|\.npmrc|credentials\.json|keyring\.)",
        "The skill may read credentials or sensitive configuration.",
        "Name the exact credential, use least privilege, and never print or transmit it.",
        "credential-access",
    ),
    _rule(
        "SECRET-001",
        Severity.CRITICAL,
        "secrets",
        "Possible hard-coded secret",
        r"(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)",
        "A value resembling a live credential is embedded in the skill.",
        "Revoke the credential, remove it from history, and load secrets from a secure store.",
        "embedded-secret",
    ),
    _rule(
        "PROMPT-001",
        Severity.HIGH,
        "prompt-injection",
        "Instruction hierarchy override",
        r"\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions?\b",
        "The skill contains language commonly used to override higher-priority instructions.",
        "Rewrite the instruction to describe the task without altering instruction hierarchy.",
        "context-influence",
    ),
    _rule(
        "PROMPT-002",
        Severity.MEDIUM,
        "prompt-injection",
        "Concealment instruction",
        r"\b(?:do not|never)\s+(?:tell|inform|reveal|show)\s+(?:the\s+)?user\b",
        "The skill tells the agent to conceal behavior from the user.",
        "Remove concealment and require transparent disclosure for consequential actions.",
        "context-influence",
    ),
    _rule(
        "OBFUSCATION-001",
        Severity.HIGH,
        "obfuscation",
        "Decode-and-execute pattern",
        r"(?:base64\.(?:b64decode|decodebytes)|base64\s+(?:-d|--decode))[^\n]{0,160}(?:eval|exec|bash|sh|powershell)",
        "Encoded content appears to be decoded and executed.",
        "Store auditable source code directly and remove runtime decoding.",
        "code-execution",
    ),
    _rule(
        "FS-WRITE-001",
        Severity.INFO,
        "filesystem",
        "Filesystem write capability",
        r"(?:open\s*\([^\n]{0,100}[\"'][wax][+b]?[\"']|\.write_text\s*\(|\.write_bytes\s*\(|\btee\s+)",
        "The skill can modify files.",
        "Constrain writes to documented output locations.",
        "filesystem-write",
    ),
    _rule(
        "FS-READ-001",
        Severity.INFO,
        "filesystem",
        "Filesystem read capability",
        r"(?:\.read_text\s*\(|\.read_bytes\s*\(|open\s*\([^\n]{0,100}[\"'][r][+b]?[\"'])",
        "The skill can read local files.",
        "Document the intended input paths and avoid broad home-directory traversal.",
        "filesystem-read",
    ),
    _rule(
        "SHELL-EXEC-001",
        Severity.INFO,
        "process",
        "Shell execution capability",
        r"(?:\|\s*|&&\s*|;\s*)(?:bash|sh|zsh|powershell|pwsh)\b",
        "The skill can invoke a command shell.",
        "Keep commands explicit, validate inputs, and avoid dynamically constructed shell text.",
        "process-execution",
    ),
    _rule(
        "PROCESS-001",
        Severity.INFO,
        "process",
        "Process execution capability",
        r"\b(?:subprocess\.|Popen\s*\(|child_process\.|Start-Process|bash\s+-c|sh\s+-c)\b",
        "The skill can start local processes.",
        "Use argument arrays, validate inputs, and document the executed programs.",
        "process-execution",
    ),
)


def scan_security(root: Path) -> tuple[list[Finding], list[Capability]]:
    findings: list[Finding] = []
    capability_evidence: dict[str, list[Evidence]] = defaultdict(list)
    per_file_capabilities: dict[str, set[str]] = defaultdict(set)

    for path in iter_files(root):
        text = read_text(path)
        if text is None:
            continue
        rel = relative(path, root)
        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule in RULES:
                if not rule.pattern.search(line):
                    continue
                evidence = Evidence(rel, line_number, clean_snippet(line))
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        title=rule.title,
                        message=rule.message,
                        evidence=evidence,
                        remediation=rule.remediation,
                    )
                )
                if rule.capability:
                    capability_evidence[rule.capability].append(evidence)
                    per_file_capabilities[rel].add(rule.capability)

    for file_name, capabilities in per_file_capabilities.items():
        if "credential-access" in capabilities and "network-access" in capabilities:
            evidence = next(
                evidence
                for evidence in capability_evidence["credential-access"]
                if evidence.file == file_name
            )
            findings.append(
                Finding(
                    rule_id="EXFIL-001",
                    severity=Severity.HIGH,
                    category="data-exfiltration",
                    title="Credential and network access combined",
                    message="The same file can access credentials and make outbound network requests.",
                    evidence=evidence,
                    remediation=(
                        "Separate credential handling from network code, restrict destinations, and add "
                        "an explicit user-approved data-flow policy."
                    ),
                )
            )

    capabilities = [
        Capability(name=name, evidence=tuple(_dedupe_evidence(items)))
        for name, items in sorted(capability_evidence.items())
    ]
    return _dedupe_findings(findings), capabilities


def _dedupe_evidence(items: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, int, str]] = set()
    result = []
    for item in items:
        key = (item.file, item.line, item.snippet)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int]] = set()
    result = []
    for item in findings:
        key = (item.rule_id, item.evidence.file, item.evidence.line)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result
