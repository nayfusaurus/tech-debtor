from __future__ import annotations

from tree_sitter import Tree, Node

from tech_debtor.config import Config
from tech_debtor.models import DebtType, Finding, Severity


def _get_imported_names(root: Node) -> list[tuple[str, Node]]:
    names = []
    for node in root.children:
        if node.type == "import_statement":
            for child in node.named_children:
                if child.type == "dotted_name":
                    first = child.named_children[0] if child.named_children else child
                    names.append((first.text.decode(), node))
        elif node.type == "import_from_statement":
            for child in node.named_children:
                if child.type == "dotted_name" and child != node.named_children[0]:
                    names.append((child.text.decode(), node))
                elif child.type == "aliased_import":
                    alias = child.child_by_field_name("alias")
                    name_node = child.child_by_field_name("name")
                    if alias:
                        names.append((alias.text.decode(), node))
                    elif name_node:
                        names.append((name_node.text.decode(), node))
    return names


def _get_all_identifiers(node: Node) -> set[str]:
    ids: set[str] = set()
    if node.type == "import_statement" or node.type == "import_from_statement":
        return ids
    if node.type == "identifier":
        ids.add(node.text.decode())
    for child in node.children:
        ids.update(_get_all_identifiers(child))
    return ids


def _get_top_level_functions(root: Node) -> list[Node]:
    return [n for n in root.children if n.type == "function_definition"]


def _func_name(node: Node) -> str:
    name_node = node.child_by_field_name("name")
    return name_node.text.decode() if name_node else "<anonymous>"


class DeadCodeAnalyzer:
    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        root = tree.root_node

        all_ids = set()
        for child in root.children:
            if child.type not in ("import_statement", "import_from_statement"):
                all_ids.update(_get_all_identifiers(child))

        for name, node in _get_imported_names(root):
            if name not in all_ids:
                findings.append(Finding(
                    file_path=file_path, line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1, debt_type=DebtType.DEAD_CODE,
                    severity=Severity.LOW, message=f"Unused import: {name}",
                    suggestion="Remove unused import", remediation_minutes=2, symbol=name,
                ))

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
                findings.append(Finding(
                    file_path=file_path, line=func.start_point[0] + 1,
                    end_line=func.end_point[0] + 1, debt_type=DebtType.DEAD_CODE,
                    severity=Severity.LOW,
                    message=f"Unused function: {name} (0 references in file)",
                    suggestion="Remove or verify if used dynamically or by external callers",
                    remediation_minutes=5, symbol=name,
                ))

        return findings
