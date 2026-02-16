"""Tests for security analyzer."""
from __future__ import annotations

from pathlib import Path

import pytest

from tech_debtor.analyzers.base import parse_python
from tech_debtor.analyzers.security import SecurityAnalyzer
from tech_debtor.config import Config
from tech_debtor.models import DebtType, Severity


@pytest.fixture
def analyzer():
    return SecurityAnalyzer()


@pytest.fixture
def config():
    return Config()


# ============================================================================
# CWE-798: Hard-Coded Credentials Tests
# ============================================================================

def test_hardcoded_password_detection(analyzer, config):
    code = 'password = "super_secret_123"'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    creds = [f for f in findings if "CWE-798" in f.message and "password" in f.message.lower()]
    assert len(creds) >= 1
    assert creds[0].severity == Severity.CRITICAL
    assert creds[0].debt_type == DebtType.SECURITY


def test_hardcoded_api_key_detection(analyzer, config):
    code = 'api_key = "my-secret-api-key-12345"'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    creds = [f for f in findings if "CWE-798" in f.message and "api_key" in f.message]
    assert len(creds) >= 1
    assert creds[0].severity == Severity.CRITICAL


def test_hardcoded_token_detection(analyzer, config):
    code = 'auth_token = "bearer_abc123def456"'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    creds = [f for f in findings if "CWE-798" in f.message and "auth_token" in f.message]
    assert len(creds) >= 1


def test_env_password_no_flag(analyzer, config):
    code = 'password = os.getenv("DB_PASSWORD")'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    creds = [f for f in findings if "CWE-798" in f.message and "Hard-coded credential" in f.message]
    assert len(creds) == 0


def test_config_password_no_flag(analyzer, config):
    code = 'password = config.get("password")'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    creds = [f for f in findings if "CWE-798" in f.message and "Hard-coded credential" in f.message]
    assert len(creds) == 0


def test_empty_string_no_flag(analyzer, config):
    code = 'password = ""'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    creds = [f for f in findings if "CWE-798" in f.message and "Hard-coded credential" in f.message]
    assert len(creds) == 0


def test_variable_assignment_no_flag(analyzer, config):
    code = "password = get_password_from_vault()"
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    creds = [f for f in findings if "CWE-798" in f.message and "Hard-coded credential" in f.message]
    assert len(creds) == 0


def test_non_credential_variable_no_flag(analyzer, config):
    code = 'name = "admin"'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    creds = [f for f in findings if "CWE-798" in f.message and "Hard-coded credential" in f.message]
    assert len(creds) == 0


def test_aws_key_pattern_detection(analyzer, config):
    code = 'key = "AKIAIOSFODNN7EXAMPLE"'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    aws = [f for f in findings if "AWS" in f.message]
    assert len(aws) >= 1
    assert aws[0].severity == Severity.CRITICAL


def test_github_token_pattern_detection(analyzer, config):
    code = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    gh = [f for f in findings if "GitHub" in f.message]
    assert len(gh) >= 1


def test_hardcoded_credentials_disabled(analyzer):
    config = Config(check_hardcoded_credentials=False)
    code = 'password = "super_secret_123"'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    creds = [f for f in findings if "CWE-798" in f.message]
    assert len(creds) == 0


# ============================================================================
# CWE-502: Unsafe Deserialization Tests
# ============================================================================

def test_pickle_loads_detection(analyzer, config):
    code = 'data = pickle.loads(user_input)'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    deser = [f for f in findings if "CWE-502" in f.message]
    assert len(deser) >= 1
    assert deser[0].severity == Severity.HIGH
    assert deser[0].debt_type == DebtType.SECURITY


def test_pickle_load_detection(analyzer, config):
    code = 'data = pickle.load(f)'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    deser = [f for f in findings if "CWE-502" in f.message]
    assert len(deser) >= 1


def test_yaml_load_no_safeloader_detection(analyzer, config):
    code = 'data = yaml.load(user_input)'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    deser = [f for f in findings if "CWE-502" in f.message]
    assert len(deser) >= 1


def test_yaml_load_with_safeloader_no_flag(analyzer, config):
    code = 'data = yaml.load(user_input, Loader=yaml.SafeLoader)'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    deser = [f for f in findings if "CWE-502" in f.message]
    assert len(deser) == 0


def test_yaml_safe_load_no_flag(analyzer, config):
    code = 'data = yaml.safe_load(user_input)'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    deser = [f for f in findings if "CWE-502" in f.message]
    assert len(deser) == 0


def test_json_loads_no_flag(analyzer, config):
    code = 'data = json.loads(user_input)'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    deser = [f for f in findings if "CWE-502" in f.message]
    assert len(deser) == 0


def test_yaml_load_csafeloader_no_flag(analyzer, config):
    code = 'data = yaml.load(user_input, Loader=yaml.CSafeLoader)'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    deser = [f for f in findings if "CWE-502" in f.message]
    assert len(deser) == 0


def test_unsafe_deserialization_disabled(analyzer):
    config = Config(check_unsafe_deserialization=False)
    code = 'data = pickle.loads(user_input)'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    deser = [f for f in findings if "CWE-502" in f.message]
    assert len(deser) == 0


# ============================================================================
# CWE-78/95: Command Injection Tests
# ============================================================================

def test_os_system_detection(analyzer, config):
    code = 'os.system("echo hello")'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    cmds = [f for f in findings if "CWE-78" in f.message]
    assert len(cmds) >= 1
    assert cmds[0].severity == Severity.CRITICAL


def test_os_popen_detection(analyzer, config):
    code = 'os.popen("ls /tmp")'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    cmds = [f for f in findings if "CWE-78" in f.message]
    assert len(cmds) >= 1
    assert cmds[0].severity == Severity.CRITICAL


def test_subprocess_shell_true_detection(analyzer, config):
    code = 'subprocess.run("echo hello", shell=True)'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    cmds = [f for f in findings if "CWE-78" in f.message]
    assert len(cmds) >= 1
    assert cmds[0].severity == Severity.HIGH


def test_subprocess_call_shell_true(analyzer, config):
    code = 'subprocess.call("echo hello", shell=True)'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    cmds = [f for f in findings if "CWE-78" in f.message]
    assert len(cmds) >= 1


def test_eval_detection(analyzer, config):
    code = 'result = eval(user_input)'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    cmds = [f for f in findings if "CWE-95" in f.message]
    assert len(cmds) >= 1
    assert cmds[0].severity == Severity.CRITICAL


def test_exec_detection(analyzer, config):
    code = 'exec(user_code)'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    cmds = [f for f in findings if "CWE-95" in f.message]
    assert len(cmds) >= 1
    assert cmds[0].severity == Severity.CRITICAL


def test_subprocess_list_no_flag(analyzer, config):
    code = 'subprocess.run(["ls", "-la"])'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    cmds = [f for f in findings if "CWE-78" in f.message]
    assert len(cmds) == 0


def test_subprocess_no_shell_no_flag(analyzer, config):
    code = 'subprocess.run(["echo", "hello"])'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    cmds = [f for f in findings if "CWE-78" in f.message]
    assert len(cmds) == 0


def test_subprocess_shell_false_no_flag(analyzer, config):
    code = 'subprocess.run("echo hello", shell=False)'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    cmds = [f for f in findings if "CWE-78" in f.message]
    assert len(cmds) == 0


def test_command_injection_disabled(analyzer):
    config = Config(check_command_injection=False)
    code = 'os.system("echo hello")'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    cmds = [f for f in findings if "CWE-78" in f.message or "CWE-95" in f.message]
    assert len(cmds) == 0


# ============================================================================
# CWE-89: SQL Injection Tests
# ============================================================================

def test_sql_concat_detection(analyzer, config):
    code = 'query = "SELECT * FROM users WHERE id=" + user_id'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    sqli = [f for f in findings if "CWE-89" in f.message]
    assert len(sqli) >= 1
    assert sqli[0].severity == Severity.HIGH
    assert sqli[0].debt_type == DebtType.SECURITY


def test_sql_fstring_detection(analyzer, config):
    code = """query = f"SELECT * FROM users WHERE name='{name}'" """
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    sqli = [f for f in findings if "CWE-89" in f.message]
    assert len(sqli) >= 1


def test_sql_delete_concat_detection(analyzer, config):
    code = 'query = "DELETE FROM sessions WHERE token=" + token'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    sqli = [f for f in findings if "CWE-89" in f.message]
    assert len(sqli) >= 1


def test_sql_update_fstring_detection(analyzer, config):
    code = """query = f"UPDATE users SET email='{email}' WHERE id={uid}" """
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    sqli = [f for f in findings if "CWE-89" in f.message]
    assert len(sqli) >= 1


def test_parameterized_query_no_flag(analyzer, config):
    code = """cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    sqli = [f for f in findings if "CWE-89" in f.message]
    assert len(sqli) == 0


def test_pure_literal_concat_no_flag(analyzer, config):
    code = 'query = "SELECT * " + "FROM users"'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    sqli = [f for f in findings if "CWE-89" in f.message]
    assert len(sqli) == 0


def test_fstring_no_interpolation_no_flag(analyzer, config):
    code = 'query = f"SELECT * FROM users"'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    sqli = [f for f in findings if "CWE-89" in f.message]
    assert len(sqli) == 0


def test_non_sql_fstring_no_flag(analyzer, config):
    code = 'msg = f"Hello {name}, welcome!"'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    sqli = [f for f in findings if "CWE-89" in f.message]
    assert len(sqli) == 0


def test_sql_injection_disabled(analyzer):
    config = Config(check_sql_injection=False)
    code = 'query = "SELECT * FROM users WHERE id=" + user_id'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    sqli = [f for f in findings if "CWE-89" in f.message]
    assert len(sqli) == 0


# ============================================================================
# CWE-477: Deprecated/Removed Stdlib Import Tests
# ============================================================================

def test_deprecated_import_imp(analyzer, config):
    code = 'import imp'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    dep = [f for f in findings if "CWE-477" in f.message]
    assert len(dep) >= 1
    assert dep[0].severity == Severity.HIGH
    assert "imp" in dep[0].message


def test_deprecated_import_distutils(analyzer, config):
    code = 'import distutils'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    dep = [f for f in findings if "CWE-477" in f.message]
    assert len(dep) >= 1
    assert dep[0].severity == Severity.HIGH


def test_deprecated_import_from_cgi(analyzer, config):
    code = 'from cgi import parse_header'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    dep = [f for f in findings if "CWE-477" in f.message]
    assert len(dep) >= 1
    assert "cgi" in dep[0].message


def test_deprecated_import_optparse(analyzer, config):
    code = 'import optparse'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    dep = [f for f in findings if "CWE-477" in f.message]
    assert len(dep) >= 1
    assert dep[0].severity == Severity.MEDIUM  # Deprecated, not removed


def test_deprecated_import_dotted(analyzer, config):
    code = 'import distutils.core'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    dep = [f for f in findings if "CWE-477" in f.message]
    assert len(dep) >= 1
    assert "distutils.core" in dep[0].message


def test_current_import_no_flag(analyzer, config):
    code = 'import importlib'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    dep = [f for f in findings if "CWE-477" in f.message]
    assert len(dep) == 0


def test_current_from_import_no_flag(analyzer, config):
    code = 'from pathlib import Path'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    dep = [f for f in findings if "CWE-477" in f.message]
    assert len(dep) == 0


def test_deprecated_imports_disabled(analyzer):
    config = Config(check_deprecated_imports=False)
    code = 'import imp'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    dep = [f for f in findings if "CWE-477" in f.message]
    assert len(dep) == 0


def test_deprecated_import_has_suggestion(analyzer, config):
    code = 'import imp'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    dep = [f for f in findings if "CWE-477" in f.message]
    assert len(dep) >= 1
    assert "importlib" in dep[0].suggestion


def test_removed_module_no_replacement(analyzer, config):
    code = 'import nntplib'
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    dep = [f for f in findings if "CWE-477" in f.message]
    assert len(dep) >= 1
    assert dep[0].severity == Severity.HIGH
    assert "no direct replacement" in dep[0].suggestion.lower()


# ============================================================================
# Integration Tests
# ============================================================================

def test_fixture_file_analysis(analyzer, config):
    fixture_path = Path(__file__).parent / "fixtures" / "security_patterns.py"
    source = fixture_path.read_text()
    tree = parse_python(source)
    findings = analyzer.analyze(str(fixture_path), source, tree, config)

    cwe_798 = [f for f in findings if "CWE-798" in f.message]
    cwe_502 = [f for f in findings if "CWE-502" in f.message]
    cwe_78 = [f for f in findings if "CWE-78" in f.message]
    cwe_95 = [f for f in findings if "CWE-95" in f.message]
    cwe_89 = [f for f in findings if "CWE-89" in f.message]
    cwe_477 = [f for f in findings if "CWE-477" in f.message]

    assert len(cwe_798) > 0, "Should detect hard-coded credentials"
    assert len(cwe_502) > 0, "Should detect unsafe deserialization"
    assert len(cwe_78) > 0, "Should detect command injection"
    assert len(cwe_95) > 0, "Should detect eval/exec"
    assert len(cwe_89) > 0, "Should detect SQL injection"
    assert len(cwe_477) > 0, "Should detect deprecated imports"


def test_all_findings_have_correct_type(analyzer, config):
    fixture_path = Path(__file__).parent / "fixtures" / "security_patterns.py"
    source = fixture_path.read_text()
    tree = parse_python(source)
    findings = analyzer.analyze(str(fixture_path), source, tree, config)

    for finding in findings:
        assert finding.debt_type == DebtType.SECURITY


def test_all_findings_have_remediation_time(analyzer, config):
    fixture_path = Path(__file__).parent / "fixtures" / "security_patterns.py"
    source = fixture_path.read_text()
    tree = parse_python(source)
    findings = analyzer.analyze(str(fixture_path), source, tree, config)

    for finding in findings:
        assert finding.remediation_minutes > 0


def test_all_findings_have_valid_severity(analyzer, config):
    fixture_path = Path(__file__).parent / "fixtures" / "security_patterns.py"
    source = fixture_path.read_text()
    tree = parse_python(source)
    findings = analyzer.analyze(str(fixture_path), source, tree, config)

    for finding in findings:
        assert finding.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
