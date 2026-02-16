from __future__ import annotations

from tree_sitter import Tree, Node

from tech_debtor.config import Config
from tech_debtor.models import DebtType, Finding, Severity


def _extract_import_names(node: Node) -> list[str]:
    """Extract bound names from an import_statement (e.g. `import os`)."""
    result: list[str] = []
    for child in node.named_children:
        if child.type == "dotted_name":
            first = child.named_children[0] if child.named_children else child
            result.append(first.text.decode() if first.text else "")
    return result


def _extract_from_import_names(node: Node) -> list[str]:
    """Extract bound names from an import_from_statement (e.g. `from os import path`)."""
    result: list[str] = []
    for child in node.named_children:
        if child.type == "dotted_name" and child != node.named_children[0]:
            result.append(child.text.decode() if child.text else "")
        elif child.type == "aliased_import":
            name = _get_aliased_import_name(child)
            if name:
                result.append(name)
    return result


def _get_aliased_import_name(node: Node) -> str | None:
    """Get the effective name from an aliased import (alias if present, else name)."""
    alias = node.child_by_field_name("alias")
    if alias and alias.text:
        return alias.text.decode()
    name_node = node.child_by_field_name("name")
    if name_node and name_node.text:
        return name_node.text.decode()
    return None


def _get_imported_names(root: Node) -> list[tuple[str, Node]]:
    names: list[tuple[str, Node]] = []
    for node in root.children:
        if node.type == "import_statement":
            for name in _extract_import_names(node):
                names.append((name, node))
        elif node.type == "import_from_statement":
            for name in _extract_from_import_names(node):
                names.append((name, node))
    return names


def _get_all_identifiers(node: Node) -> set[str]:
    ids: set[str] = set()
    if node.type == "import_statement" or node.type == "import_from_statement":
        return ids
    if node.type == "identifier":
        ids.add(node.text.decode() if node.text else "")
    for child in node.children:
        ids.update(_get_all_identifiers(child))
    return ids


def _get_top_level_functions(root: Node) -> list[Node]:
    return [n for n in root.children if n.type == "function_definition"]


def _func_name(node: Node) -> str:
    name_node = node.child_by_field_name("name")
    return name_node.text.decode() if name_node and name_node.text else "<anonymous>"


class DeadCodeAnalyzer:
    def analyze(
        self, file_path: str, source: str, tree: Tree, config: Config
    ) -> list[Finding]:
        findings: list[Finding] = []
        root = tree.root_node

        all_ids = set()
        for child in root.children:
            if child.type not in ("import_statement", "import_from_statement"):
                all_ids.update(_get_all_identifiers(child))

        for name, node in _get_imported_names(root):
            if name not in all_ids:
                findings.append(
                    Finding(
                        file_path=file_path,
                        line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        debt_type=DebtType.DEAD_CODE,
                        severity=Severity.LOW,
                        message=f"Unused import: {name}",
                        suggestion="Remove unused import",
                        remediation_minutes=2,
                        symbol=name,
                    )
                )

        usage_ids: set[str] = set()
        top_funcs = _get_top_level_functions(root)

        for child in root.children:
            if child.type == "function_definition":
                body = child.child_by_field_name("body")
                if body:
                    usage_ids.update(_get_all_identifiers(body))
            elif child.type not in ("import_statement", "import_from_statement"):
                usage_ids.update(_get_all_identifiers(child))

        _SKIP_NAMES = {"main"}

        for func in top_funcs:
            name = _func_name(func)
            if name.startswith("_") or name in _SKIP_NAMES:
                continue
            if name not in usage_ids:
                findings.append(
                    Finding(
                        file_path=file_path,
                        line=func.start_point[0] + 1,
                        end_line=func.end_point[0] + 1,
                        debt_type=DebtType.DEAD_CODE,
                        severity=Severity.LOW,
                        message=f"Unused function: {name} (0 references in file)",
                        suggestion="Remove or verify if used dynamically or by external callers",
                        remediation_minutes=5,
                        symbol=name,
                    )
                )

        return findings
