from __future__ import annotations

from tree_sitter import Tree, Node

from tech_debtor.analyzers.base import _find_nodes
from tech_debtor.config import Config
from tech_debtor.models import DebtType, Finding, Severity

# Constants for resource functions that should use context managers
RESOURCE_FUNCTIONS = {
    "open", "socket", "socket.socket", "sqlite3.connect",
    "urllib.request.urlopen", "tempfile.NamedTemporaryFile",
}

# Broad exception types that are typically too generic
BROAD_EXCEPTION_TYPES = {"Exception", "BaseException"}


# ============================================================================
# Helper Functions
# ============================================================================

def _find_first_identifier_text(node: Node) -> str | None:
    """Find first identifier child and return its decoded text."""
    for child in node.children:
        if child.type == "identifier":
            return child.text.decode() if child.text else None
    return None


def _get_exception_type(except_clause: Node) -> str | None:
    """Extract exception type from except clause."""
    for child in except_clause.children:
        if child.type == "identifier":
            return child.text.decode() if child.text else None
        # Handle `except ValueError as e:` and `except (ValueError, TypeError):`
        if child.type in ("as_pattern", "tuple"):
            result = _find_first_identifier_text(child)
            if result is not None:
                return result
    return None


def _is_swallowed_exception(block: Node) -> bool:
    """Check if except block only contains 'pass' (swallows exception)."""
    if not block:
        return True

    # Get the actual block content
    if block.type == "block":
        statements = [c for c in block.children if c.type != ":" and c.type != "comment"]
        if len(statements) == 0:
            return True
        if len(statements) == 1 and statements[0].type == "pass_statement":
            return True

    return False


def _is_within_with_statement(node: Node) -> bool:
    """Check if node is within a with statement's body."""
    current = node.parent
    while current:
        if current.type == "with_statement":
            return True
        # Stop at function/class boundaries
        if current.type in ("function_definition", "class_definition", "module"):
            return False
        current = current.parent
    return False


def _is_singleton(node: Node) -> bool:
    """Check if node is None, True, or False."""
    if not node:
        return False
    return node.type in ("none", "true", "false") or \
           (node.type == "identifier" and node.text is not None and node.text.decode() in ("None", "True", "False"))


def _get_call_name(call_node: Node) -> str:
    """Extract function name from call node."""
    func = call_node.child_by_field_name("function")
    if not func or not func.text:
        return "<unknown>"

    # Handle simple calls: open()
    if func.type == "identifier":
        return func.text.decode()

    # Handle attribute calls: socket.socket(), sqlite3.connect()
    if func.type == "attribute":
        # Get full dotted name
        return func.text.decode()

    return func.text.decode()


def _is_float_literal(node: Node) -> bool:
    """Check if node is a float literal."""
    if node.type == "float":
        return True
    # Also check for expressions that might result in floats
    if node.type == "binary_operator":
        # Check children recursively
        for child in node.children:
            if _is_float_literal(child):
                return True
    return False


def _has_guard_condition(var_name: str, func_node: Node) -> bool:
    """Check if there's a guard condition checking if variable is non-zero."""
    # Look for patterns like: if var != 0, if var, etc.
    # This is a simplified check - look for if statements in the same function
    if_statements = _find_nodes(func_node, "if_statement")

    for if_stmt in if_statements:
        condition = if_stmt.child_by_field_name("condition")
        if condition and condition.text:
            cond_text = condition.text.decode()
            if var_name in cond_text:
                if "!= 0" in cond_text or "!= 0.0" in cond_text:
                    return True
                if "> 0" in cond_text or "< 0" in cond_text:
                    return True

    return False


def _get_containing_function(node: Node) -> Node | None:
    """Get the function definition containing this node."""
    current = node.parent
    while current:
        if current.type == "function_definition":
            return current
        if current.type == "module":
            return None
        current = current.parent
    return None


def _get_division_operator(op: Node) -> str | None:
    """Extract division operator (/, //, %) from a binary_operator node."""
    for child in op.children:
        if child.type in ("/", "//", "%"):
            return child.type
    # Fallback: check text content
    op_text = op.text.decode() if op.text else ""
    if "//" in op_text:
        return "//"
    if "/" in op_text:
        return "/"
    if "%" in op_text:
        return "%"
    return None


def _check_zero_literal_division(op: Node, right: Node, file_path: str) -> Finding | None:
    """Return a Finding if right operand is a zero literal, else None."""
    if not right.text:
        return None
    try:
        value = float(right.text.decode())
    except ValueError:
        return None
    if value != 0:
        return None
    return Finding(
        file_path=file_path,
        line=op.start_point[0] + 1,
        end_line=op.end_point[0] + 1,
        debt_type=DebtType.EXCEPTION,
        severity=Severity.CRITICAL,
        message="CWE-369: Division by zero literal",
        suggestion="Remove division by zero",
        remediation_minutes=5,
    )


def _check_unguarded_variable_division(op: Node, right: Node, file_path: str) -> Finding | None:
    """Return a Finding if division by variable lacks a zero guard, else None."""
    if right.type != "identifier" or not right.text:
        return None
    var_name = right.text.decode()
    func = _get_containing_function(op)
    if func and _has_guard_condition(var_name, func):
        return None
    return Finding(
        file_path=file_path,
        line=op.start_point[0] + 1,
        end_line=op.end_point[0] + 1,
        debt_type=DebtType.EXCEPTION,
        severity=Severity.MEDIUM,
        message=f"CWE-369: Division by variable '{var_name}' without zero check",
        suggestion=f"Add guard: if {var_name} != 0: before division",
        remediation_minutes=10,
    )


# ============================================================================
# ExceptionAnalyzer Class
# ============================================================================

class ExceptionAnalyzer:
    """Detects exception handling anti-patterns (ISO 5055 Reliability)."""

    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]:
        findings = []
        root = tree.root_node

        # CWE-703: Improper Exception Handling (always enabled with config toggles)
        findings.extend(self._detect_improper_exception_handling(root, file_path, config))

        if config.check_resource_leaks:
            findings.extend(self._detect_missing_resource_release(root, file_path, config))

        if config.check_float_comparison:
            findings.extend(self._detect_float_comparison(root, file_path, config))

        if config.check_object_comparison:
            findings.extend(self._detect_object_reference_comparison(root, file_path, config))

        if config.check_divide_by_zero:
            findings.extend(self._detect_divide_by_zero(root, file_path, config))

        if config.check_uncaught_exceptions:
            findings.extend(self._detect_uncaught_exceptions(root, file_path, config))

        if config.check_unchecked_returns:
            findings.extend(self._detect_unchecked_return_values(root, file_path, config))

        return findings

    def _detect_improper_exception_handling(
        self, root: Node, file_path: str, config: Config
    ) -> list[Finding]:
        """Detect CWE-703: bare except, broad catches, swallowed exceptions."""
        findings = []
        except_clauses = _find_nodes(root, "except_clause")

        for clause in except_clauses:
            line = clause.start_point[0] + 1
            end_line = clause.end_point[0] + 1

            exception_type = _get_exception_type(clause)

            # Check for bare except (no exception type)
            if exception_type is None and not config.allow_bare_except:
                findings.append(Finding(
                    file_path=file_path,
                    line=line,
                    end_line=end_line,
                    debt_type=DebtType.EXCEPTION,
                    severity=Severity.HIGH,
                    message="CWE-703: Bare except clause catches all exceptions including system exits",
                    suggestion="Specify exception type(s) explicitly, e.g., 'except ValueError:' or 'except (TypeError, KeyError):'",
                    remediation_minutes=5,
                ))

            # Check for broad exception types
            elif exception_type in BROAD_EXCEPTION_TYPES and not config.allow_broad_except:
                findings.append(Finding(
                    file_path=file_path,
                    line=line,
                    end_line=end_line,
                    debt_type=DebtType.EXCEPTION,
                    severity=Severity.MEDIUM,
                    message=f"CWE-703: Overly broad exception catch ({exception_type})",
                    suggestion="Catch specific exception types (ValueError, TypeError, etc.) instead of broad Exception",
                    remediation_minutes=5,
                ))

            # Check for swallowed exceptions (except: pass)
            block = None
            for child in clause.children:
                if child.type == "block":
                    block = child
                    break

            if block and _is_swallowed_exception(block):
                findings.append(Finding(
                    file_path=file_path,
                    line=line,
                    end_line=end_line,
                    debt_type=DebtType.EXCEPTION,
                    severity=Severity.HIGH,
                    message="CWE-703: Exception silently swallowed (pass statement only)",
                    suggestion="Log the exception, re-raise it, or handle it explicitly",
                    remediation_minutes=10,
                ))

        return findings

    def _detect_missing_resource_release(
        self, root: Node, file_path: str, config: Config
    ) -> list[Finding]:
        """Detect CWE-772: resource acquisition without context manager."""
        findings = []
        calls = _find_nodes(root, "call")

        for call in calls:
            call_name = _get_call_name(call)

            # Check if this is a resource function
            is_resource = False
            for resource_func in RESOURCE_FUNCTIONS:
                if call_name == resource_func or call_name.endswith(f".{resource_func}"):
                    is_resource = True
                    break

            if not is_resource:
                continue

            # Check if it's already in a with statement
            if _is_within_with_statement(call):
                continue

            # Found a resource leak
            line = call.start_point[0] + 1
            end_line = call.end_point[0] + 1

            findings.append(Finding(
                file_path=file_path,
                line=line,
                end_line=end_line,
                debt_type=DebtType.EXCEPTION,
                severity=Severity.HIGH,
                message=f"CWE-772: Resource '{call_name}' opened without context manager",
                suggestion=f"Use 'with {call_name}(...) as resource:' to ensure proper cleanup",
                remediation_minutes=10,
                symbol=call_name,
            ))

        return findings

    def _detect_float_comparison(
        self, root: Node, file_path: str, config: Config
    ) -> list[Finding]:
        """Detect CWE-1077: floating point comparison with == or !=."""
        findings = []
        comparisons = _find_nodes(root, "comparison_operator")

        for comp in comparisons:
            # Get the operator
            operator_text = comp.text.decode() if comp.text else ""

            # Only flag == and != for floats
            if "==" not in operator_text and "!=" not in operator_text:
                continue

            # Check if any operand is a float
            has_float = False
            for child in comp.children:
                if _is_float_literal(child):
                    has_float = True
                    break

            if not has_float:
                continue

            line = comp.start_point[0] + 1
            end_line = comp.end_point[0] + 1

            findings.append(Finding(
                file_path=file_path,
                line=line,
                end_line=end_line,
                debt_type=DebtType.EXCEPTION,
                severity=Severity.MEDIUM,
                message="CWE-1077: Floating point comparison using == or != is unreliable",
                suggestion="Use math.isclose() for floating point comparisons",
                remediation_minutes=5,
            ))

        return findings

    def _detect_object_reference_comparison(
        self, root: Node, file_path: str, config: Config
    ) -> list[Finding]:
        """Detect CWE-595: comparing objects with 'is' instead of '=='."""
        findings = []
        comparisons = _find_nodes(root, "comparison_operator")

        for comp in comparisons:
            # Check if this comparison uses 'is' or 'is not' operator
            has_is_operator = False
            for child in comp.children:
                if child.type in ("is", "is not"):
                    has_is_operator = True
                    break

            if not has_is_operator:
                continue

            # Get operands (filter out 'is', 'is not', and 'not' keywords)
            operands = [c for c in comp.children if c.type not in ("is", "is not", "not")]

            # Check if any operand is a singleton (None, True, False)
            # If ANY operand is a singleton, this is a valid use of 'is'
            has_singleton = any(_is_singleton(op) for op in operands)

            if has_singleton:
                continue

            line = comp.start_point[0] + 1
            end_line = comp.end_point[0] + 1

            findings.append(Finding(
                file_path=file_path,
                line=line,
                end_line=end_line,
                debt_type=DebtType.EXCEPTION,
                severity=Severity.MEDIUM,
                message="CWE-595: Object comparison using 'is' instead of '=='",
                suggestion="Use '==' for value comparison; 'is' should only be used with None, True, False",
                remediation_minutes=5,
            ))

        return findings

    def _detect_divide_by_zero(
        self, root: Node, file_path: str, config: Config
    ) -> list[Finding]:
        """Detect CWE-369: division by variable without zero check."""
        findings: list[Finding] = []

        for op in _find_nodes(root, "binary_operator"):
            if not _get_division_operator(op):
                continue
            right = op.child_by_field_name("right")
            if not right:
                continue

            if right.type in ("integer", "float"):
                finding = _check_zero_literal_division(op, right, file_path)
                if finding:
                    findings.append(finding)
                continue

            finding = _check_unguarded_variable_division(op, right, file_path)
            if finding:
                findings.append(finding)

        return findings

    def _detect_uncaught_exceptions(
        self, root: Node, file_path: str, config: Config
    ) -> list[Finding]:
        """Detect CWE-248: uncaught exceptions (opt-in, high false positives)."""
        findings = []
        # This is a simplified implementation - just look for raise statements
        # outside of try/except blocks
        raise_stmts = _find_nodes(root, "raise_statement")

        for raise_stmt in raise_stmts:
            # Check if it's inside a try block
            current = raise_stmt.parent
            in_try_except = False

            while current:
                if current.type == "try_statement":
                    in_try_except = True
                    break
                if current.type in ("function_definition", "module"):
                    break
                current = current.parent

            if not in_try_except:
                line = raise_stmt.start_point[0] + 1
                end_line = raise_stmt.end_point[0] + 1

                findings.append(Finding(
                    file_path=file_path,
                    line=line,
                    end_line=end_line,
                    debt_type=DebtType.EXCEPTION,
                    severity=Severity.LOW,
                    message="CWE-248: Exception raised without try/except handler",
                    suggestion="Consider wrapping in try/except or document that caller must handle",
                    remediation_minutes=5,
                ))

        return findings

    def _detect_unchecked_return_values(
        self, root: Node, file_path: str, config: Config
    ) -> list[Finding]:
        """Detect CWE-252: unchecked return values (opt-in, very high false positives)."""
        findings = []

        # Look for expression statements that are just function calls
        # (i.e., return value is ignored)
        expr_stmts = _find_nodes(root, "expression_statement")

        for expr_stmt in expr_stmts:
            # Check if it's a call
            call = None
            for child in expr_stmt.children:
                if child.type == "call":
                    call = child
                    break

            if not call:
                continue

            # Skip common side-effect functions
            call_name = _get_call_name(call)
            side_effect_functions = {
                "print", "append", "extend", "remove", "pop", "clear",
                "update", "add", "write", "close", "flush", "seek",
            }

            if any(call_name.endswith(f) for f in side_effect_functions):
                continue

            line = expr_stmt.start_point[0] + 1
            end_line = expr_stmt.end_point[0] + 1

            findings.append(Finding(
                file_path=file_path,
                line=line,
                end_line=end_line,
                debt_type=DebtType.EXCEPTION,
                severity=Severity.LOW,
                message=f"CWE-252: Return value of '{call_name}' is not checked",
                suggestion="Assign return value to variable or explicitly ignore with '_'",
                remediation_minutes=5,
                symbol=call_name,
            ))

        return findings
