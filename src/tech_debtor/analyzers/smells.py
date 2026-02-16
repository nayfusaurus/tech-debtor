from __future__ import annotations

from tree_sitter import Tree, Node

from tech_debtor.analyzers.base import tree_to_functions, tree_to_classes, _find_nodes
from tech_debtor.config import Config
from tech_debtor.models import DebtType, Finding, Severity

GOD_CLASS_METHOD_THRESHOLD = 20


def _func_name(node: Node) -> str:
    name_node = node.child_by_field_name("name")
    return name_node.text.decode() if name_node and name_node.text else "<anonymous>"


def _class_name(node: Node) -> str:
    name_node = node.child_by_field_name("name")
    return name_node.text.decode() if name_node and name_node.text else "<anonymous>"


def _function_length(func_node: Node) -> int:
    return func_node.end_point[0] - func_node.start_point[0]


def _max_nesting_depth(node: Node, current: int = 0) -> int:
    nesting_types = {
        "if_statement",
        "for_statement",
        "while_statement",
        "with_statement",
        "try_statement",
    }
    max_depth = current
    for child in node.children:
        if child.type in nesting_types:
            max_depth = max(max_depth, _max_nesting_depth(child, current + 1))
        else:
            max_depth = max(max_depth, _max_nesting_depth(child, current))
    return max_depth


def _param_count(func_node: Node) -> int:
    params = func_node.child_by_field_name("parameters")
    if params is None:
        return 0
    count = 0
    for child in params.named_children:
        if child.type in (
            "identifier",
            "typed_parameter",
            "default_parameter",
            "typed_default_parameter",
            "list_splat_pattern",
            "dictionary_splat_pattern",
        ):
            text = child.text.decode() if child.text else ""
            if text not in ("self", "cls"):
                count += 1
    return count


class SmellAnalyzer:
    def analyze(
        self, file_path: str, source: str, tree: Tree, config: Config
    ) -> list[Finding]:
        findings: list[Finding] = []
        functions = tree_to_functions(tree.root_node)

        for func in functions:
            name = _func_name(func)
            line = func.start_point[0] + 1
            end_line = func.end_point[0] + 1

            length = _function_length(func)
            if length > config.max_function_length:
                excess = length - config.max_function_length
                findings.append(
                    Finding(
                        file_path=file_path,
                        line=line,
                        end_line=end_line,
                        debt_type=DebtType.SMELL,
                        severity=Severity.HIGH
                        if excess > config.max_function_length
                        else Severity.MEDIUM,
                        message=f"Long function: {length} lines (threshold: {config.max_function_length})",
                        suggestion="Extract logic into smaller, focused functions",
                        remediation_minutes=max(5, excess * 2),
                        symbol=name,
                    )
                )

            body = func.child_by_field_name("body")
            if body:
                depth = _max_nesting_depth(body)
                if depth > config.max_nesting_depth:
                    findings.append(
                        Finding(
                            file_path=file_path,
                            line=line,
                            end_line=end_line,
                            debt_type=DebtType.SMELL,
                            severity=Severity.HIGH
                            if depth > config.max_nesting_depth + 2
                            else Severity.MEDIUM,
                            message=f"Deep nesting: depth {depth} (threshold: {config.max_nesting_depth})",
                            suggestion="Use early returns, extract nested logic into functions",
                            remediation_minutes=max(
                                5, (depth - config.max_nesting_depth) * 10
                            ),
                            symbol=name,
                        )
                    )

            param_count = _param_count(func)
            if param_count > config.max_parameters:
                findings.append(
                    Finding(
                        file_path=file_path,
                        line=line,
                        end_line=end_line,
                        debt_type=DebtType.SMELL,
                        severity=Severity.MEDIUM,
                        message=f"Too many parameters: {param_count} (threshold: {config.max_parameters})",
                        suggestion="Group parameters into a dataclass or configuration object",
                        remediation_minutes=max(
                            5, (param_count - config.max_parameters) * 5
                        ),
                        symbol=name,
                    )
                )

        classes = tree_to_classes(tree.root_node)
        for cls in classes:
            cls_name = _class_name(cls)
            methods = _find_nodes(cls, "function_definition")
            method_count = len(methods)
            if method_count > GOD_CLASS_METHOD_THRESHOLD:
                findings.append(
                    Finding(
                        file_path=file_path,
                        line=cls.start_point[0] + 1,
                        end_line=cls.end_point[0] + 1,
                        debt_type=DebtType.SMELL,
                        severity=Severity.HIGH,
                        message=f"God class: {method_count} methods (threshold: {GOD_CLASS_METHOD_THRESHOLD})",
                        suggestion="Split into focused classes using single-responsibility principle",
                        remediation_minutes=method_count * 5,
                        symbol=cls_name,
                    )
                )

        return findings
