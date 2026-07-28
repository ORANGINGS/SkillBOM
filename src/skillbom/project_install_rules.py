from __future__ import annotations

import json
import re
from pathlib import Path

from skillbom.models import Evidence, Finding, Severity
from skillbom.utils import clean_snippet


def scan_install_hooks(root: Path) -> tuple[list[Finding], dict[str, list[Evidence]]]:
    findings: list[Finding] = []
    capabilities: dict[str, list[Evidence]] = {}
    package_json = root / "package.json"
    if not package_json.is_file():
        return findings, capabilities
    try:
        package = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return findings, capabilities
    scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
    if not isinstance(scripts, dict):
        return findings, capabilities
    for hook in ("preinstall", "install", "postinstall"):
        command = scripts.get(hook)
        if not isinstance(command, str) or not command.strip():
            continue
        evidence = Evidence(
            "package.json", _line_containing(package_json, f'"{hook}"'), clean_snippet(command)
        )
        remote_exec = re.search(
            r"(?:curl|wget|Invoke-WebRequest)[^\n|;&]*(?:\||&&|;)\s*"
            r"(?:bash|sh|zsh|powershell|pwsh|node)",
            command,
            re.IGNORECASE,
        )
        if remote_exec:
            findings.append(
                Finding(
                    "NODE-INSTALL-REMOTE-001",
                    Severity.CRITICAL,
                    "supply-chain",
                    "Install hook downloads and executes remote content",
                    f"npm {hook} downloads remote content and executes it during installation.",
                    evidence,
                    "Remove network execution from install hooks; pin and verify packaged artifacts.",
                )
            )
            capabilities.setdefault("code-execution", []).append(evidence)
            capabilities.setdefault("network-access", []).append(evidence)
        else:
            findings.append(
                Finding(
                    "NODE-INSTALL-HOOK-001",
                    Severity.MEDIUM,
                    "supply-chain",
                    "Package installation hook",
                    f"npm {hook} executes automatically when dependencies are installed.",
                    evidence,
                    "Keep install hooks minimal, deterministic, documented, and offline.",
                )
            )
            capabilities.setdefault("package-install", []).append(evidence)
            capabilities.setdefault("process-execution", []).append(evidence)
    return findings, capabilities


def _line_containing(path: Path, token: str) -> int:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return 1
    offset = text.find(token)
    return text.count("\n", 0, max(0, offset)) + 1
