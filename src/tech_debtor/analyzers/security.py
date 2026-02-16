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
    "password",
    "passwd",
    "pwd",
    "secret",
    "secret_key",
    "api_key",
    "apikey",
    "token",
    "auth_token",
    "access_token",
    "authorization",
    "credential",
    "credentials",
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
    "pickle.loads",
    "pickle.load",
    "marshal.loads",
    "marshal.load",
    "shelve.open",
    "dill.loads",
    "dill.load",
}

# CWE-78: Subprocess functions dangerous with shell=True
SUBPROCESS_FUNCTIONS = {
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
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

# CWE-477: Deprecated/removed stdlib modules
DEPRECATED_STDLIB_MODULES: dict[str, tuple[str, str, str]] = {
    # module: (replacement, severity_hint, reason)
    # Removed in 3.12
    "imp": ("importlib", "removed", "Removed in Python 3.12"),
    "distutils": ("setuptools", "removed", "Removed in Python 3.12"),
    # Deprecated in 3.11, removed in 3.13
    "cgi": ("multipart", "removed", "Removed in Python 3.13"),
    "cgitb": ("traceback", "removed", "Removed in Python 3.13"),
    "pipes": ("subprocess", "removed", "Removed in Python 3.13"),
    # Removed in 3.13
    "nntplib": ("", "removed", "Removed in Python 3.13 (no replacement)"),
    "telnetlib": ("", "removed", "Removed in Python 3.13 (no replacement)"),
    "imghdr": ("", "removed", "Removed in Python 3.13 (use python-magic or filetype)"),
    "sndhdr": ("", "removed", "Removed in Python 3.13 (no replacement)"),
    "audioop": ("", "removed", "Removed in Python 3.13 (no replacement)"),
    "aifc": ("", "removed", "Removed in Python 3.13 (no replacement)"),
    "chunk": ("", "removed", "Removed in Python 3.13 (no replacement)"),
    "sunau": ("", "removed", "Removed in Python 3.13 (no replacement)"),
    "xdrlib": ("", "removed", "Removed in Python 3.13 (no replacement)"),
    "uu": ("base64", "removed", "Removed in Python 3.13"),
    # Deprecated (still importable but discouraged)
    "optparse": ("argparse", "deprecated", "Deprecated since Python 3.2"),
    "formatter": ("", "deprecated", "Deprecated since Python 3.4 (no replacement)"),
    "msilib": ("", "deprecated", "Deprecated since Python 3.11 (Windows only)"),
}


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


def _get_kwarg_value(child: Node, key: str) -> str | None:
    """Get value of a keyword argument if it matches the key, else None."""
    name_node = child.child_by_field_name("name")
    if not name_node or _get_node_text(name_node) != key:
        return None
    value_node = child.child_by_field_name("value")
    return _get_node_text(value_node) if value_node else None


def _has_keyword_argument(
    call_node: Node, key: str, values: set[str] | None = None
) -> bool:
    """Check if a call has a specific keyword argument with optional value matching."""
    args = call_node.child_by_field_name("arguments")
    if not args:
        return False
    for child in args.children:
        if child.type != "keyword_argument":
            continue
        val = _get_kwarg_value(child, key)
        if val is None:
            continue
        if values is None:
            return True
        if val in values:
            return True
    return False


def _matches_credential_keyword(name: str) -> bool:
    """Check if variable name matches common credential patterns."""
    name_lower = name.lower()
    return any(keyword in name_lower for keyword in CREDENTIAL_KEYWORDS)


def _get_string_content(node: Node) -> str:
    """Get the content of a string node, stripping quotes and prefixes."""
    text = _get_node_text(node)
    for prefix in (
        'f"""',
        "f'''",
        'f"',
        "f'",
        'b"""',
        "b'''",
        'b"',
        "b'",
        '"""',
        "'''",
        '"',
        "'",
    ):
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    for suffix in ('"""', "'''", '"', "'"):
        if text.endswith(suffix):
            text = text[: -len(suffix)]
            break
    return text


def _string_contains_sql(text: str) -> bool:
    """Check if a string contains SQL keywords."""
    return bool(SQL_KEYWORD_PATTERN.search(text))


def _is_fstring(text: str) -> bool:
    """Check if text represents an f-string literal."""
    return text.startswith(('f"', "f'", 'f"""', "f'''"))


def _check_api_key_match(text: str) -> str | None:
    """Return API key description if text matches a known pattern, else None."""
    for pattern, description in API_KEY_PATTERNS:
        if pattern.search(text):
            return description
    return None


def _get_module_name_from_node(node: Node, node_type: str) -> str | None:
    """Extract module name from an import node. Returns None to skip."""
    if node_type == "import_from_statement":
        module_node = node.child_by_field_name("module_name")
        return _get_node_text(module_node) if module_node else None
    # import_statement: find first dotted_name child
    for child in node.children:
        if child.type == "dotted_name":
            return _get_node_text(child)
    return None


def _has_sql_concat(op: Node) -> bool:
    """Check if a binary_operator has SQL string + non-literal (injection risk)."""
    op_text = _get_node_text(op)
    if "+" not in op_text:
        return False
    has_sql_string = False
    has_non_literal = False
    for child in op.children:
        if child.type == "string" and _string_contains_sql(_get_string_content(child)):
            has_sql_string = True
        elif child.type not in ("+", "string"):
            has_non_literal = True
    return has_sql_string and has_non_literal


def _is_sql_fstring(string_node: Node) -> bool:
    """Check if a string node is an f-string with SQL keywords and interpolation."""
    text = _get_node_text(string_node)
    if not text or not _is_fstring(text):
        return False
    content = _get_string_content(string_node)
    if not _string_contains_sql(content):
        return False
    return bool(_find_nodes(string_node, "interpolation"))


def _make_finding(
    file_path: str,
    node: Node,
    severity: Severity,
    message: str,
    suggestion: str,
    minutes: int,
    symbol: str | None = None,
) -> Finding:
    """Create a security Finding from a node."""
    return Finding(
        file_path=file_path,
        line=node.start_point[0] + 1,
        end_line=node.end_point[0] + 1,
        debt_type=DebtType.SECURITY,
        severity=severity,
        message=message,
        suggestion=suggestion,
        remediation_minutes=minutes,
        symbol=symbol,
    )


# ============================================================================
# SecurityAnalyzer Class
# ============================================================================


class SecurityAnalyzer:
    """Detects security anti-patterns (OWASP/CWE Security)."""

    def analyze(
        self, file_path: str, source: str, tree: Tree, config: Config
    ) -> list[Finding]:
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

        if config.check_deprecated_imports:
            findings.extend(self._detect_deprecated_imports(root, file_path))

        return findings

    def _detect_hardcoded_credentials(
        self, root: Node, file_path: str
    ) -> list[Finding]:
        """Detect CWE-798: hard-coded credentials in assignments and API key patterns."""
        findings: list[Finding] = []
        self._check_credential_assignments(root, file_path, findings)
        self._check_api_key_strings(root, file_path, findings)
        return findings

    def _check_credential_assignments(
        self, root: Node, file_path: str, findings: list[Finding]
    ) -> None:
        """Part A: Find assignments where credential-named variable = string literal."""
        for assign in _find_nodes(root, "assignment"):
            left = assign.child_by_field_name("left")
            right = assign.child_by_field_name("right")
            if not left or not right:
                continue

            var_name = _get_node_text(left)
            if not var_name or not _matches_credential_keyword(var_name):
                continue
            if right.type != "string":
                continue

            string_content = _get_string_content(right)
            if not string_content or string_content.strip() == "":
                continue

            findings.append(
                _make_finding(
                    file_path,
                    assign,
                    Severity.CRITICAL,
                    f"CWE-798: Hard-coded credential in variable '{var_name}'",
                    "Use environment variables (os.getenv()) or a secrets manager instead of hard-coding credentials",
                    15,
                    symbol=var_name,
                )
            )

    def _check_api_key_strings(
        self, root: Node, file_path: str, findings: list[Finding]
    ) -> None:
        """Part B: Find string literals matching known API key patterns."""
        for string_node in _find_nodes(root, "string"):
            text = _get_string_content(string_node)
            if not text:
                continue
            description = _check_api_key_match(text)
            if description:
                findings.append(
                    _make_finding(
                        file_path,
                        string_node,
                        Severity.CRITICAL,
                        f"CWE-798: Possible {description} found in string literal",
                        "Remove hard-coded keys; use environment variables or a secrets manager",
                        15,
                    )
                )

    def _detect_unsafe_deserialization(
        self, root: Node, file_path: str
    ) -> list[Finding]:
        """Detect CWE-502: use of unsafe deserialization functions."""
        findings: list[Finding] = []

        for call in _find_nodes(root, "call"):
            call_name = _get_call_name(call)

            if call_name in ("yaml.load", "yaml.unsafe_load"):
                if call_name == "yaml.load":
                    safe_loaders = {
                        "SafeLoader",
                        "yaml.SafeLoader",
                        "CSafeLoader",
                        "yaml.CSafeLoader",
                    }
                    if _has_keyword_argument(call, "Loader", safe_loaders):
                        continue
                findings.append(
                    _make_finding(
                        file_path,
                        call,
                        Severity.HIGH,
                        f"CWE-502: Unsafe deserialization via '{call_name}' allows arbitrary code execution",
                        "Use yaml.safe_load() or pass Loader=yaml.SafeLoader explicitly",
                        10,
                        symbol=call_name,
                    )
                )
                continue

            if call_name in UNSAFE_DESERIALIZE_FUNCTIONS:
                findings.append(
                    _make_finding(
                        file_path,
                        call,
                        Severity.HIGH,
                        f"CWE-502: Unsafe deserialization via '{call_name}' allows arbitrary code execution",
                        f"Avoid '{call_name}'; use JSON or other safe serialization formats for untrusted data",
                        20,
                        symbol=call_name,
                    )
                )

        return findings

    def _detect_command_injection(self, root: Node, file_path: str) -> list[Finding]:
        """Detect CWE-78: OS command injection and CWE-95: code injection."""
        findings: list[Finding] = []

        for call in _find_nodes(root, "call"):
            call_name = _get_call_name(call)

            if call_name in CODE_EXEC_FUNCTIONS:
                findings.append(
                    _make_finding(
                        file_path,
                        call,
                        Severity.CRITICAL,
                        f"CWE-95: Use of '{call_name}()' allows arbitrary code execution",
                        f"Avoid '{call_name}()'; use ast.literal_eval() for data or safer alternatives",
                        30,
                        symbol=call_name,
                    )
                )
            elif call_name in ALWAYS_DANGEROUS_COMMANDS:
                findings.append(
                    _make_finding(
                        file_path,
                        call,
                        Severity.CRITICAL,
                        f"CWE-78: '{call_name}()' is vulnerable to command injection",
                        "Use subprocess.run() with a list of arguments (no shell=True)",
                        20,
                        symbol=call_name,
                    )
                )
            elif call_name in SUBPROCESS_FUNCTIONS and _has_keyword_argument(
                call, "shell", {"True"}
            ):
                findings.append(
                    _make_finding(
                        file_path,
                        call,
                        Severity.HIGH,
                        f"CWE-78: '{call_name}()' called with shell=True is vulnerable to command injection",
                        "Pass arguments as a list without shell=True: subprocess.run(['cmd', 'arg1', 'arg2'])",
                        15,
                        symbol=call_name,
                    )
                )

        return findings

    def _detect_sql_injection(self, root: Node, file_path: str) -> list[Finding]:
        """Detect CWE-89: SQL injection via string concatenation or f-strings."""
        findings: list[Finding] = []

        for op in _find_nodes(root, "binary_operator"):
            if _has_sql_concat(op):
                findings.append(
                    _make_finding(
                        file_path,
                        op,
                        Severity.HIGH,
                        "CWE-89: Possible SQL injection via string concatenation",
                        "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
                        15,
                    )
                )

        for string_node in _find_nodes(root, "string"):
            if _is_sql_fstring(string_node):
                findings.append(
                    _make_finding(
                        file_path,
                        string_node,
                        Severity.HIGH,
                        "CWE-89: Possible SQL injection via f-string interpolation",
                        "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
                        15,
                    )
                )

        return findings

    def _detect_deprecated_imports(self, root: Node, file_path: str) -> list[Finding]:
        """Detect CWE-477: use of deprecated or removed stdlib modules."""
        findings: list[Finding] = []

        for node_type in ("import_statement", "import_from_statement"):
            for node in _find_nodes(root, node_type):
                module_name = _get_module_name_from_node(node, node_type)
                if not module_name:
                    continue

                top_module = module_name.split(".")[0]
                if top_module not in DEPRECATED_STDLIB_MODULES:
                    continue

                replacement, severity_hint, reason = DEPRECATED_STDLIB_MODULES[
                    top_module
                ]
                severity = (
                    Severity.HIGH if severity_hint == "removed" else Severity.MEDIUM
                )
                suggestion = (
                    f"Replace '{top_module}' with '{replacement}'"
                    if replacement
                    else f"Remove usage of '{top_module}' — no direct replacement"
                )

                findings.append(
                    _make_finding(
                        file_path,
                        node,
                        severity,
                        f"CWE-477: Import of deprecated/removed module '{module_name}' ({reason})",
                        suggestion,
                        15,
                        symbol=module_name,
                    )
                )

        return findings
