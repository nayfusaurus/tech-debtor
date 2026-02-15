from __future__ import annotations

from tree_sitter import Tree, Node

from tech_debtor.analyzers.base import tree_to_functions
from tech_debtor.config import Config
from tech_debtor.models import DebtType, Finding, Severity

CYCLOMATIC_BRANCH_TYPES = {
    "if_statement", "elif_clause", "for_statement", "while_statement",
    "except_clause", "with_statement", "assert_statement",
}

BOOLEAN_OPERATORS = {"and", "or"}

COGNITIVE_INCREMENT_TYPES = {
    "if_statement", "for_statement", "while_statement", "except_clause",
}

COGNITIVE_NO_NESTING_TYPES = {"elif_clause", "else_clause"}


def _count_nodes(node: Node, target_types: set[str]) -> int:
    count = 0
    if node.type in target_types:
        count += 1
    for child in node.children:
        count += _count_nodes(child, target_types)
    return count


def _count_boolean_operators(node: Node) -> int:
    count = 0
    if node.type == "boolean_operator":
        count += 1
    for child in node.children:
        count += _count_boolean_operators(child)
    return count


def _cognitive_complexity(node: Node, nesting: int = 0) -> int:
    total = 0
    for child in node.children:
        if child.type in COGNITIVE_INCREMENT_TYPES:
            total += 1 + nesting
            total += _cognitive_complexity(child, nesting + 1)
        elif child.type in COGNITIVE_NO_NESTING_TYPES:
            total += 1
            total += _cognitive_complexity(child, nesting)
        elif child.type == "boolean_operator":
            total += 1
            total += _cognitive_complexity(child, nesting)
        else:
            total += _cognitive_complexity(child, nesting)
    return total


def _func_name(func_node: Node) -> str:
    name_node = func_node.child_by_field_name("name")
    return name_node.text.decode() if name_node and name_node.text else "<anonymous>"


def _severity_for_excess(excess: int, threshold: int) -> Severity:
    ratio = excess / max(threshold, 1)
    if ratio >= 2.0:
        return Severity.CRITICAL
    if ratio >= 1.0:
        return Severity.HIGH
    if ratio >= 0.5:
        return Severity.MEDIUM
    return Severity.LOW


def _remediation_minutes(excess: int) -> int:
    return max(5, excess * 5)


class ComplexityAnalyzer:
    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        functions = tree_to_functions(tree.root_node)

        for func in functions:
            name = _func_name(func)
            body = func.child_by_field_name("body")
            if body is None:
                continue

            branches = _count_nodes(body, CYCLOMATIC_BRANCH_TYPES)
            bool_ops = _count_boolean_operators(body)
            cyclomatic = 1 + branches + bool_ops

            if cyclomatic > config.max_complexity:
                excess = cyclomatic - config.max_complexity
                findings.append(Finding(
                    file_path=file_path, line=func.start_point[0] + 1,
                    end_line=func.end_point[0] + 1, debt_type=DebtType.COMPLEXITY,
                    severity=_severity_for_excess(excess, config.max_complexity),
                    message=f"Cyclomatic complexity: {cyclomatic} (threshold: {config.max_complexity})",
                    suggestion="Break into smaller functions, extract conditional logic",
                    remediation_minutes=_remediation_minutes(excess), symbol=name,
                ))

            cognitive = _cognitive_complexity(body)
            if cognitive > config.max_cognitive_complexity:
                excess = cognitive - config.max_cognitive_complexity
                findings.append(Finding(
                    file_path=file_path, line=func.start_point[0] + 1,
                    end_line=func.end_point[0] + 1, debt_type=DebtType.COMPLEXITY,
                    severity=_severity_for_excess(excess, config.max_cognitive_complexity),
                    message=f"Cognitive complexity: {cognitive} (threshold: {config.max_cognitive_complexity})",
                    suggestion="Reduce nesting depth, extract helper functions, simplify conditionals",
                    remediation_minutes=_remediation_minutes(excess), symbol=name,
                ))

        return findings
