from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from skillbom.models import Dependency, Evidence
from skillbom.utils import clean_snippet, domain_from_url, extract_urls, iter_files, read_text, relative

SHELL_TOOLS = {
    "git",
    "gh",
    "curl",
    "wget",
    "jq",
    "docker",
    "python",
    "python3",
    "node",
    "npm",
    "pnpm",
    "yarn",
    "uv",
    "pip",
    "pip3",
    "powershell",
    "pwsh",
}
IMPORT_RE = re.compile(r"(?:require\s*\(|from\s+)[\"'](?P<name>[^\"']+)[\"']")
COMMAND_RE = re.compile(r"(?:^|[;&|]\s*|`)(?P<tool>[A-Za-z][A-Za-z0-9._-]*)\b")


def scan_dependencies(root: Path, metadata: dict[str, object]) -> list[Dependency]:
    dependencies: list[Dependency] = []

    allowed_tools = metadata.get("allowed-tools")
    if isinstance(allowed_tools, str):
        for token in allowed_tools.split():
            name = token.split("(", 1)[0]
            dependencies.append(
                Dependency("agent-tool", name, Evidence("SKILL.md", 1, f"allowed-tools: {allowed_tools}"))
            )
    elif isinstance(allowed_tools, list):
        for token in allowed_tools:
            if isinstance(token, str):
                dependencies.append(
                    Dependency("agent-tool", token, Evidence("SKILL.md", 1, f"allowed-tools: {token}"))
                )

    for path in iter_files(root):
        text = read_text(path)
        if text is None:
            continue
        rel = relative(path, root)

        for url in extract_urls(text):
            domain = domain_from_url(url)
            if domain:
                line = _line_containing(text, url)
                dependencies.append(
                    Dependency("service", domain, Evidence(rel, line, clean_snippet(url)))
                )

        if path.suffix == ".py":
            dependencies.extend(_python_dependencies(text, rel))
        elif path.suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx"}:
            for match in IMPORT_RE.finditer(text):
                name = match.group("name").split("/", 1)[0]
                dependencies.append(
                    Dependency(
                        "node-package",
                        name,
                        Evidence(rel, text.count("\n", 0, match.start()) + 1, clean_snippet(match.group(0))),
                    )
                )
        elif path.suffix in {".sh", ".bash", ".zsh", ".ps1"}:
            for line_number, line in enumerate(text.splitlines(), start=1):
                for match in COMMAND_RE.finditer(line):
                    tool = match.group("tool")
                    if tool in SHELL_TOOLS:
                        dependencies.append(
                            Dependency("system-tool", tool, Evidence(rel, line_number, clean_snippet(line)))
                        )

        if path.name == "package.json":
            try:
                package = json.loads(text)
            except json.JSONDecodeError:
                package = {}
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                values = package.get(section, {})
                if isinstance(values, dict):
                    for name in values:
                        dependencies.append(
                            Dependency("node-package", name, Evidence(rel, 1, f"{section}: {name}"))
                        )

        if path.name in {"requirements.txt", "requirements-dev.txt"}:
            for line_number, line in enumerate(text.splitlines(), start=1):
                cleaned = line.strip()
                if not cleaned or cleaned.startswith(("#", "-")):
                    continue
                name = re.split(r"[<>=!~\[]", cleaned, maxsplit=1)[0].strip()
                if name:
                    dependencies.append(
                        Dependency("python-package", name, Evidence(rel, line_number, clean_snippet(line)))
                    )

    return _dedupe(dependencies)


def _python_dependencies(text: str, rel: str) -> list[Dependency]:
    result: list[Dependency] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return result
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.split(".", 1)[0]
                result.append(
                    Dependency("python-import", name, Evidence(rel, node.lineno, f"import {alias.name}"))
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            name = node.module.split(".", 1)[0]
            result.append(
                Dependency("python-import", name, Evidence(rel, node.lineno, f"from {node.module} import …"))
            )
    return result


def _line_containing(text: str, value: str) -> int:
    offset = text.find(value)
    return text.count("\n", 0, max(offset, 0)) + 1


def _dedupe(items: list[Dependency]) -> list[Dependency]:
    seen: set[tuple[str, str]] = set()
    result = []
    for item in items:
        key = (item.kind, item.name)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return sorted(result, key=lambda item: (item.kind, item.name))
