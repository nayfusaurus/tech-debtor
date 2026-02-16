from __future__ import annotations

from tree_sitter import Tree, Node

from tech_debtor.analyzers.base import tree_to_functions
from tech_debtor.config import Config
from tech_debtor.models import DebtType, Finding, Severity

MIN_LINES_FOR_DUPLICATE = 4


def _normalize_tree(node: Node) -> str:
    if node.child_count == 0:
        return node.type
    children = " ".join(_normalize_tree(c) for c in node.children)
    return f"({node.type} {children})"


def _func_name(node: Node) -> str:
    name_node = node.child_by_field_name("name")
    return name_node.text.decode() if name_node and name_node.text else "<anonymous>"


class DuplicationAnalyzer:
    def analyze(
        self, file_path: str, source: str, tree: Tree, config: Config
    ) -> list[Finding]:
        findings: list[Finding] = []
        functions = tree_to_functions(tree.root_node)

        candidates: list[tuple[Node, str]] = []
        for func in functions:
            length = func.end_point[0] - func.start_point[0]
            if length >= MIN_LINES_FOR_DUPLICATE:
                body = func.child_by_field_name("body")
                if body:
                    fingerprint = _normalize_tree(body)
                    candidates.append((func, fingerprint))

        seen: dict[str, list[Node]] = {}
        for func, fp in candidates:
            seen.setdefault(fp, []).append(func)

        reported: set[tuple[str, ...]] = set()
        for fp, funcs in seen.items():
            if len(funcs) < 2:
                continue
            names = [_func_name(f) for f in funcs]
            key = tuple(sorted(names))
            if key in reported:
                continue
            reported.add(key)

            first = funcs[0]
            length = first.end_point[0] - first.start_point[0]
            locations = ", ".join(
                f"{_func_name(f)} (line {f.start_point[0] + 1})" for f in funcs
            )
            findings.append(
                Finding(
                    file_path=file_path,
                    line=first.start_point[0] + 1,
                    end_line=first.end_point[0] + 1,
                    debt_type=DebtType.DUPLICATION,
                    severity=Severity.HIGH if length > 15 else Severity.MEDIUM,
                    message=f"Duplicate code blocks ({length} lines): {locations}",
                    suggestion="Extract shared logic into a common function",
                    remediation_minutes=max(10, length * 2),
                    symbol=_func_name(first),
                )
            )

        return findings
