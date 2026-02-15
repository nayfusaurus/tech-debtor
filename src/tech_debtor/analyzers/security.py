from __future__ import annotations

import re

from tree_sitter import Tree, Node

from tech_debtor.analyzers.base import _find_nodes
from tech_debtor.config import Config
from tech_debtor.models import DebtType, Finding, Severity

# ============================================================================
# Constants
# ============================================================================

# CWE-798: Credential variable name keywords (matched case-insensitively)
CREDENTIAL_KEYWORDS = {
    "password", "passwd", "pwd",
    "secret", "secret_key",
    "api_key", "apikey",
    "token", "auth_token", "access_token",
    "authorization",
    "credential", "credentials",
    "private_key",
}

# CWE-798: Known API key regex patterns
API_KEY_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub Personal Access Token"),
    (re.compile(r"gho_[A-Za-z0-9]{36}"), "GitHub OAuth Token"),
    (re.compile(r"ghs_[A-Za-z0-9]{36}"), "GitHub Server Token"),
    (re.compile(r"xoxb-[0-9A-Za-z\-]+"), "Slack Bot Token"),
    (re.compile(r"xoxp-[0-9A-Za-z\-]+"), "Slack User Token"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "Secret Key (generic)"),
]

# CWE-502: Dangerous deserialization functions
UNSAFE_DESERIALIZE_FUNCTIONS = {
    "pickle.loads", "pickle.load",
    "marshal.loads", "marshal.load",
    "shelve.open",
    "dill.loads", "dill.load",
}

# CWE-78: Subprocess functions dangerous with shell=True
SUBPROCESS_FUNCTIONS = {
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "subprocess.check_call", "subprocess.check_output",
}

# CWE-78: Always-dangerous OS command functions
ALWAYS_DANGEROUS_COMMANDS = {"os.system", "os.popen"}

# CWE-95: Code execution functions
CODE_EXEC_FUNCTIONS = {"eval", "exec"}

# CWE-89: SQL keyword pattern
SQL_KEYWORD_PATTERN = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|FROM|WHERE|CREATE|ALTER|TRUNCATE)\b",
    re.IGNORECASE,
)


# ============================================================================
# Helper Functions
# ============================================================================

def _get_call_name(call_node: Node) -> str:
    """Extract function name from call node (dotted or simple)."""
    func = call_node.child_by_field_name("function")
    if not func or not func.text:
        return "<unknown>"
    return func.text.decode()


def _get_node_text(node: Node) -> str:
    """Safely get text from a node."""
    if node and node.text:
        return node.text.decode()
    return ""


def _has_keyword_argument(call_node: Node, key: str, values: set[str] | None = None) -> bool:
    """Check if a call has a specific keyword argument with optional value matching."""
    args = call_node.child_by_field_name("arguments")
    if not args:
        return False
    for child in args.children:
        if child.type == "keyword_argument":
            name_node = child.child_by_field_name("name")
            if name_node and _get_node_text(name_node) == key:
                if values is None:
                    return True
                value_node = child.child_by_field_name("value")
                if value_node:
                    val_text = _get_node_text(value_node)
                    if val_text in values:
                        return True
    return False


def _matches_credential_keyword(name: str) -> bool:
    """Check if variable name matches common credential patterns."""
    name_lower = name.lower()
    for keyword in CREDENTIAL_KEYWORDS:
        if keyword in name_lower:
            return True
    return False


def _get_string_content(node: Node) -> str:
    """Get the content of a string node, stripping quotes and prefixes."""
    text = _get_node_text(node)
    # Strip surrounding quotes and prefixes
    for prefix in ('f"""', "f'''", 'f"', "f'", 'b"""', "b'''", 'b"', "b'", '"""', "'''", '"', "'"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    for suffix in ('"""', "'''", '"', "'"):
        if text.endswith(suffix):
            text = text[:-len(suffix)]
            break
    return text


def _string_contains_sql(text: str) -> bool:
    """Check if a string contains SQL keywords."""
    return bool(SQL_KEYWORD_PATTERN.search(text))


# ============================================================================
# SecurityAnalyzer Class
# ============================================================================

class SecurityAnalyzer:
    """Detects security anti-patterns (OWASP/CWE Security)."""

    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        root = tree.root_node

        if config.check_hardcoded_credentials:
            findings.extend(self._detect_hardcoded_credentials(root, file_path))

        if config.check_unsafe_deserialization:
            findings.extend(self._detect_unsafe_deserialization(root, file_path))

        if config.check_command_injection:
            findings.extend(self._detect_command_injection(root, file_path))

        if config.check_sql_injection:
            findings.extend(self._detect_sql_injection(root, file_path))

        return findings

    def _detect_hardcoded_credentials(
        self, root: Node, file_path: str
    ) -> list[Finding]:
        """Detect CWE-798: hard-coded credentials in assignments and API key patterns."""
        findings: list[Finding] = []

        # Part A: Assignment-based detection
        assignments = _find_nodes(root, "assignment")
        for assign in assignments:
            left = assign.child_by_field_name("left")
            right = assign.child_by_field_name("right")

            if not left or not right:
                continue

            var_name = _get_node_text(left)
            if not var_name:
                continue

            # Check if variable name matches credential keywords
            if not _matches_credential_keyword(var_name):
                continue

            # Only flag if right side is a string literal (not a function call, variable, etc.)
            if right.type != "string":
                continue

            # Skip empty strings (placeholder patterns)
            string_content = _get_string_content(right)
            if not string_content or string_content.strip() == "":
                continue

            line = assign.start_point[0] + 1
            end_line = assign.end_point[0] + 1

            findings.append(Finding(
                file_path=file_path,
                line=line,
                end_line=end_line,
                debt_type=DebtType.SECURITY,
                severity=Severity.CRITICAL,
                message=f"CWE-798: Hard-coded credential in variable '{var_name}'",
                suggestion="Use environment variables (os.getenv()) or a secrets manager instead of hard-coding credentials",
                remediation_minutes=15,
                symbol=var_name,
            ))

        # Part B: API key pattern detection in all string literals
        strings = _find_nodes(root, "string")
        for string_node in strings:
            text = _get_string_content(string_node)
            if not text:
                continue

            for pattern, description in API_KEY_PATTERNS:
                if pattern.search(text):
                    line = string_node.start_point[0] + 1
                    end_line = string_node.end_point[0] + 1

                    findings.append(Finding(
                        file_path=file_path,
                        line=line,
                        end_line=end_line,
                        debt_type=DebtType.SECURITY,
                        severity=Severity.CRITICAL,
                        message=f"CWE-798: Possible {description} found in string literal",
                        suggestion="Remove hard-coded keys; use environment variables or a secrets manager",
                        remediation_minutes=15,
                    ))
                    break  # One finding per string

        return findings

    def _detect_unsafe_deserialization(
        self, root: Node, file_path: str
    ) -> list[Finding]:
        """Detect CWE-502: use of unsafe deserialization functions."""
        findings: list[Finding] = []
        calls = _find_nodes(root, "call")

        for call in calls:
            call_name = _get_call_name(call)

            # Check for yaml.load without SafeLoader
            if call_name in ("yaml.load", "yaml.unsafe_load"):
                if call_name == "yaml.load":
                    safe_loaders = {"SafeLoader", "yaml.SafeLoader", "CSafeLoader", "yaml.CSafeLoader"}
                    if _has_keyword_argument(call, "Loader", safe_loaders):
                        continue  # Safe usage

                line = call.start_point[0] + 1
                end_line = call.end_point[0] + 1

                findings.append(Finding(
                    file_path=file_path,
                    line=line,
                    end_line=end_line,
                    debt_type=DebtType.SECURITY,
                    severity=Severity.HIGH,
                    message=f"CWE-502: Unsafe deserialization via '{call_name}' allows arbitrary code execution",
                    suggestion="Use yaml.safe_load() or pass Loader=yaml.SafeLoader explicitly",
                    remediation_minutes=10,
                    symbol=call_name,
                ))
                continue

            # Check for other unsafe deserialization functions
            if call_name in UNSAFE_DESERIALIZE_FUNCTIONS:
                line = call.start_point[0] + 1
                end_line = call.end_point[0] + 1

                findings.append(Finding(
                    file_path=file_path,
                    line=line,
                    end_line=end_line,
                    debt_type=DebtType.SECURITY,
                    severity=Severity.HIGH,
                    message=f"CWE-502: Unsafe deserialization via '{call_name}' allows arbitrary code execution",
                    suggestion=f"Avoid '{call_name}'; use JSON or other safe serialization formats for untrusted data",
                    remediation_minutes=20,
                    symbol=call_name,
                ))

        return findings

    def _detect_command_injection(
        self, root: Node, file_path: str
    ) -> list[Finding]:
        """Detect CWE-78: OS command injection and CWE-95: code injection."""
        findings: list[Finding] = []
        calls = _find_nodes(root, "call")

        for call in calls:
            call_name = _get_call_name(call)
            line = call.start_point[0] + 1
            end_line = call.end_point[0] + 1

            # CWE-95: eval() and exec() are always dangerous
            if call_name in CODE_EXEC_FUNCTIONS:
                findings.append(Finding(
                    file_path=file_path,
                    line=line,
                    end_line=end_line,
                    debt_type=DebtType.SECURITY,
                    severity=Severity.CRITICAL,
                    message=f"CWE-95: Use of '{call_name}()' allows arbitrary code execution",
                    suggestion=f"Avoid '{call_name}()'; use ast.literal_eval() for data or safer alternatives",
                    remediation_minutes=30,
                    symbol=call_name,
                ))
                continue

            # CWE-78: os.system / os.popen are always dangerous
            if call_name in ALWAYS_DANGEROUS_COMMANDS:
                findings.append(Finding(
                    file_path=file_path,
                    line=line,
                    end_line=end_line,
                    debt_type=DebtType.SECURITY,
                    severity=Severity.CRITICAL,
                    message=f"CWE-78: '{call_name}()' is vulnerable to command injection",
                    suggestion="Use subprocess.run() with a list of arguments (no shell=True)",
                    remediation_minutes=20,
                    symbol=call_name,
                ))
                continue

            # CWE-78: subprocess with shell=True
            if call_name in SUBPROCESS_FUNCTIONS:
                if _has_keyword_argument(call, "shell", {"True"}):
                    findings.append(Finding(
                        file_path=file_path,
                        line=line,
                        end_line=end_line,
                        debt_type=DebtType.SECURITY,
                        severity=Severity.HIGH,
                        message=f"CWE-78: '{call_name}()' called with shell=True is vulnerable to command injection",
                        suggestion="Pass arguments as a list without shell=True: subprocess.run(['cmd', 'arg1', 'arg2'])",
                        remediation_minutes=15,
                        symbol=call_name,
                    ))

        return findings

    def _detect_sql_injection(
        self, root: Node, file_path: str
    ) -> list[Finding]:
        """Detect CWE-89: SQL injection via string concatenation or f-strings."""
        findings: list[Finding] = []

        # Part A: String concatenation with SQL keywords
        binary_ops = _find_nodes(root, "binary_operator")
        for op in binary_ops:
            op_text = _get_node_text(op)
            if "+" not in op_text:
                continue

            has_sql_string = False
            has_non_literal = False
            for child in op.children:
                if child.type == "string":
                    content = _get_string_content(child)
                    if _string_contains_sql(content):
                        has_sql_string = True
                elif child.type not in ("+",):
                    if child.type != "string":
                        has_non_literal = True

            if has_sql_string and has_non_literal:
                line = op.start_point[0] + 1
                end_line = op.end_point[0] + 1

                findings.append(Finding(
                    file_path=file_path,
                    line=line,
                    end_line=end_line,
                    debt_type=DebtType.SECURITY,
                    severity=Severity.HIGH,
                    message="CWE-89: Possible SQL injection via string concatenation",
                    suggestion="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
                    remediation_minutes=15,
                ))

        # Part B: f-strings with SQL keywords
        strings = _find_nodes(root, "string")
        for string_node in strings:
            text = _get_node_text(string_node)
            if not text:
                continue

            # Check if it's an f-string
            if not (text.startswith('f"') or text.startswith("f'") or
                    text.startswith('f"""') or text.startswith("f'''")):
                continue

            # Check for SQL keywords
            content = _get_string_content(string_node)
            if not _string_contains_sql(content):
                continue

            # Check for interpolation children
            interpolations = _find_nodes(string_node, "interpolation")
            if not interpolations:
                continue

            line = string_node.start_point[0] + 1
            end_line = string_node.end_point[0] + 1

            findings.append(Finding(
                file_path=file_path,
                line=line,
                end_line=end_line,
                debt_type=DebtType.SECURITY,
                severity=Severity.HIGH,
                message="CWE-89: Possible SQL injection via f-string interpolation",
                suggestion="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
                remediation_minutes=15,
            ))

        return findings
