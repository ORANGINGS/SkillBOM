from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path

from skillbom.models import Evidence
from skillbom.parser import discover_skills
from skillbom.utils import clean_snippet, iter_files, read_text, relative

MCP_DEPENDENCIES = {
    "@modelcontextprotocol/sdk",
    "mcp",
    "fastmcp",
    "modelcontextprotocol",
}
AGENT_DEPENDENCIES = {
    "openai-agents",
    "langchain",
    "langgraph",
    "llama-index",
    "llama_index",
    "crewai",
    "autogen",
    "semantic-kernel",
    "semantic_kernel",
}


@dataclass(slots=True, frozen=True)
class ExposedTool:
    name: str
    framework: str
    evidence: Evidence



def detect_project_types(root: Path) -> list[str]:
    project_types: set[str] = set()
    if discover_skills(root):
        project_types.add("agent-skill")

    dependencies = _manifest_dependency_names(root)
    lowered_dependencies = {item.lower() for item in dependencies}
    if lowered_dependencies & MCP_DEPENDENCIES:
        project_types.add("mcp-server")
    if lowered_dependencies & AGENT_DEPENDENCIES:
        project_types.add("agent-integration")

    for path in iter_files(root):
        text = read_text(path)
        if text is None:
            continue
        lowered = text.lower()
        if any(
            marker in lowered
            for marker in (
                "@modelcontextprotocol/sdk",
                "from mcp.server",
                "import fastmcp",
                "from fastmcp",
                "fastmcp(",
                "mcpserver(",
                "server.tool(",
                "@mcp.tool",
            )
        ):
            project_types.add("mcp-server")
        if any(
            marker in lowered
            for marker in (
                "from agents import agent",
                "from langchain",
                "from langgraph",
                "from crewai",
                "import autogen",
                "semantic_kernel",
            )
        ):
            project_types.add("agent-integration")
    if not project_types:
        project_types.add("ai-tool-project")
    return sorted(project_types)


def discover_exposed_tools(root: Path) -> list[ExposedTool]:
    tools: list[ExposedTool] = []
    for path in iter_files(root):
        text = read_text(path)
        if text is None:
            continue
        rel = relative(path, root)
        if path.suffix == ".py":
            tools.extend(_python_mcp_tools(text, rel))
        elif path.suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx"}:
            patterns = (
                ("mcp", re.compile(r"\b(?:server|mcp)\.tool\s*\(\s*[\"']([^\"']+)[\"']")),
                ("mcp", re.compile(r"\bregisterTool\s*\(\s*[\"']([^\"']+)[\"']")),
            )
            for framework, pattern in patterns:
                for match in pattern.finditer(text):
                    tools.append(
                        ExposedTool(
                            match.group(1),
                            framework,
                            Evidence(rel, text.count("\n", 0, match.start()) + 1, clean_snippet(match.group(0))),
                        )
                    )
    seen: set[tuple[str, str, str, int]] = set()
    result: list[ExposedTool] = []
    for item in tools:
        key = (item.name, item.framework, item.evidence.file, item.evidence.line)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return sorted(result, key=lambda item: (item.framework, item.name, item.evidence.file, item.evidence.line))



def _python_mcp_tools(text: str, rel: str) -> list[ExposedTool]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    result: list[ExposedTool] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = _ast_name(target)
            if name.endswith(".tool") or name in {"tool", "mcp_tool"}:
                result.append(
                    ExposedTool(
                        node.name,
                        "mcp",
                        Evidence(rel, node.lineno, f"def {node.name}(…):"),
                    )
                )
    return result


def _ast_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _ast_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _manifest_dependency_names(root: Path) -> set[str]:
    names: set[str] = set()
    package_json = root / "package.json"
    if package_json.is_file():
        try:
            package = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            package = {}
        if isinstance(package, dict):
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                values = package.get(section, {})
                if isinstance(values, dict):
                    names.update(str(name) for name in values)
    for requirements in root.glob("requirements*.txt"):
        try:
            lines = requirements.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for line in lines:
            cleaned = line.strip()
            if cleaned and not cleaned.startswith(("#", "-")):
                names.add(re.split(r"[<>=!~\[]", cleaned, maxsplit=1)[0].strip())
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        text = read_text(pyproject) or ""
        for match in re.finditer(r"[\"']([A-Za-z0-9_.@/-]+)(?:\[[^\]]+\])?(?:[<>=!~].*)?[\"']", text):
            names.add(match.group(1))
    return names


