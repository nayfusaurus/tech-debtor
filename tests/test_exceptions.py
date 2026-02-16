"""Tests for exception handling analyzer."""

from __future__ import annotations

import pytest
from pathlib import Path

from tech_debtor.analyzers.base import parse_python
from tech_debtor.analyzers.exceptions import ExceptionAnalyzer
from tech_debtor.config import Config
from tech_debtor.models import DebtType, Severity


@pytest.fixture
def analyzer():
    return ExceptionAnalyzer()


@pytest.fixture
def config():
    return Config()


# ============================================================================
# CWE-703: Bare Except Tests
# ============================================================================


def test_bare_except_detection(analyzer, config):
    """Bare except clause should be flagged."""
    code = """
try:
    x = 1
except:
    pass
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    bare_excepts = [f for f in findings if "Bare except" in f.message]
    assert len(bare_excepts) == 1
    assert bare_excepts[0].severity == Severity.HIGH
    assert bare_excepts[0].debt_type == DebtType.EXCEPTION
    assert "CWE-703" in bare_excepts[0].message


def test_bare_except_with_config_allow(analyzer):
    """Bare except should not be flagged if allowed in config."""
    config = Config(allow_bare_except=True)
    code = """
try:
    x = 1
except:
    pass
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    bare_excepts = [f for f in findings if "Bare except" in f.message]
    assert len(bare_excepts) == 0


def test_specific_except_no_flag(analyzer, config):
    """Specific exception types should not be flagged."""
    code = """
try:
    x = 1
except ValueError:
    pass
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    bare_excepts = [f for f in findings if "Bare except" in f.message]
    assert len(bare_excepts) == 0


def test_multiple_exception_types_no_flag(analyzer, config):
    """Multiple specific exception types should not be flagged."""
    code = """
try:
    x = 1
except (ValueError, TypeError):
    pass
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    bare_excepts = [f for f in findings if "Bare except" in f.message]
    assert len(bare_excepts) == 0


# ============================================================================
# CWE-703: Broad Exception Tests
# ============================================================================


def test_broad_exception_detection(analyzer, config):
    """Catching Exception should be flagged as too broad."""
    code = """
try:
    x = 1
except Exception:
    log(x)
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    broad_excepts = [f for f in findings if "broad" in f.message.lower()]
    assert len(broad_excepts) == 1
    assert broad_excepts[0].severity == Severity.MEDIUM
    assert "Exception" in broad_excepts[0].message


def test_base_exception_detection(analyzer, config):
    """Catching BaseException should be flagged as too broad."""
    code = """
try:
    x = 1
except BaseException:
    log(x)
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    broad_excepts = [f for f in findings if "broad" in f.message.lower()]
    assert len(broad_excepts) == 1
    assert "BaseException" in broad_excepts[0].message


def test_broad_exception_with_config_allow(analyzer):
    """Broad exception should not be flagged if allowed in config."""
    config = Config(allow_broad_except=True)
    code = """
try:
    x = 1
except Exception:
    log(x)
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    broad_excepts = [f for f in findings if "broad" in f.message.lower()]
    assert len(broad_excepts) == 0


# ============================================================================
# CWE-703: Swallowed Exception Tests
# ============================================================================


def test_swallowed_exception_detection(analyzer, config):
    """Exception with only pass statement should be flagged."""
    code = """
try:
    x = 1
except ValueError:
    pass
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    swallowed = [f for f in findings if "swallowed" in f.message.lower()]
    assert len(swallowed) == 1
    assert swallowed[0].severity == Severity.HIGH


def test_exception_with_handling_no_flag(analyzer, config):
    """Exception with actual handling should not be flagged."""
    code = """
try:
    x = 1
except ValueError:
    log("error")
    raise
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    swallowed = [f for f in findings if "swallowed" in f.message.lower()]
    assert len(swallowed) == 0


# ============================================================================
# CWE-772: Resource Leak Tests
# ============================================================================


def test_resource_leak_open(analyzer, config):
    """open() without context manager should be flagged."""
    code = """
f = open("file.txt")
data = f.read()
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    leaks = [f for f in findings if "CWE-772" in f.message]
    assert len(leaks) == 1
    assert leaks[0].severity == Severity.HIGH
    assert "open" in leaks[0].message


def test_resource_leak_socket(analyzer, config):
    """socket.socket() without context manager should be flagged."""
    code = """
import socket
s = socket.socket()
s.connect(("localhost", 8080))
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    leaks = [f for f in findings if "CWE-772" in f.message]
    assert len(leaks) == 1
    assert "socket" in leaks[0].message.lower()


def test_with_statement_no_leak(analyzer, config):
    """Using with statement should not be flagged."""
    code = """
with open("file.txt") as f:
    data = f.read()
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    leaks = [f for f in findings if "CWE-772" in f.message]
    assert len(leaks) == 0


def test_resource_leak_disabled(analyzer):
    """Resource leaks should not be checked if disabled in config."""
    config = Config(check_resource_leaks=False)
    code = """
f = open("file.txt")
data = f.read()
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    leaks = [f for f in findings if "CWE-772" in f.message]
    assert len(leaks) == 0


# ============================================================================
# CWE-1077: Float Comparison Tests
# ============================================================================


def test_float_comparison_equality(analyzer, config):
    """Comparing floats with == should be flagged."""
    code = """
if 0.1 + 0.2 == 0.3:
    print("equal")
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    float_comps = [f for f in findings if "CWE-1077" in f.message]
    assert len(float_comps) == 1
    assert float_comps[0].severity == Severity.MEDIUM


def test_float_comparison_inequality(analyzer, config):
    """Comparing floats with != should be flagged."""
    code = """
if value != 3.14159:
    print("not equal")
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    float_comps = [f for f in findings if "CWE-1077" in f.message]
    assert len(float_comps) == 1


def test_integer_comparison_no_flag(analyzer, config):
    """Integer comparison should not be flagged."""
    code = """
if 1 + 2 == 3:
    print("equal")
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    float_comps = [f for f in findings if "CWE-1077" in f.message]
    assert len(float_comps) == 0


def test_float_comparison_disabled(analyzer):
    """Float comparison should not be checked if disabled."""
    config = Config(check_float_comparison=False)
    code = """
if 0.1 + 0.2 == 0.3:
    print("equal")
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    float_comps = [f for f in findings if "CWE-1077" in f.message]
    assert len(float_comps) == 0


# ============================================================================
# CWE-595: Object Reference Comparison Tests
# ============================================================================


def test_object_comparison_is(analyzer, config):
    """Comparing non-singletons with 'is' should be flagged."""
    code = """
if name is "admin":
    print("admin")
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    obj_comps = [f for f in findings if "CWE-595" in f.message]
    assert len(obj_comps) == 1
    assert obj_comps[0].severity == Severity.MEDIUM


def test_object_comparison_is_not(analyzer, config):
    """Comparing non-singletons with 'is not' should be flagged."""
    code = """
if value is not "expected":
    print("unexpected")
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    obj_comps = [f for f in findings if "CWE-595" in f.message]
    assert len(obj_comps) == 1


def test_none_comparison_no_flag(analyzer, config):
    """Comparing with None using 'is' should not be flagged."""
    code = """
if value is None:
    print("none")
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    obj_comps = [f for f in findings if "CWE-595" in f.message]
    assert len(obj_comps) == 0


def test_true_false_comparison_no_flag(analyzer, config):
    """Comparing with True/False using 'is' should not be flagged."""
    code = """
if flag is True:
    print("true")
if flag is False:
    print("false")
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    obj_comps = [f for f in findings if "CWE-595" in f.message]
    assert len(obj_comps) == 0


def test_equality_comparison_no_flag(analyzer, config):
    """Using == for comparison should not be flagged."""
    code = """
if name == "admin":
    print("admin")
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    obj_comps = [f for f in findings if "CWE-595" in f.message]
    assert len(obj_comps) == 0


def test_object_comparison_disabled(analyzer):
    """Object comparison should not be checked if disabled."""
    config = Config(check_object_comparison=False)
    code = """
if name is "admin":
    print("admin")
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    obj_comps = [f for f in findings if "CWE-595" in f.message]
    assert len(obj_comps) == 0


# ============================================================================
# CWE-369: Divide by Zero Tests
# ============================================================================


def test_divide_by_variable(analyzer, config):
    """Division by variable without guard should be flagged."""
    code = """
def calc(x, y):
    return x / y
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    div_zero = [f for f in findings if "CWE-369" in f.message]
    assert len(div_zero) == 1
    assert div_zero[0].severity == Severity.MEDIUM


def test_modulo_by_variable(analyzer, config):
    """Modulo by variable without guard should be flagged."""
    code = """
def calc(x, y):
    return x % y
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    div_zero = [f for f in findings if "CWE-369" in f.message]
    assert len(div_zero) == 1


def test_floor_divide_by_variable(analyzer, config):
    """Floor division by variable without guard should be flagged."""
    code = """
def calc(x, y):
    return x // y
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    div_zero = [f for f in findings if "CWE-369" in f.message]
    assert len(div_zero) == 1


def test_divide_by_zero_literal(analyzer, config):
    """Division by zero literal should be flagged as critical."""
    code = """
x = 10 / 0
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    div_zero = [f for f in findings if "CWE-369" in f.message]
    assert len(div_zero) == 1
    assert div_zero[0].severity == Severity.CRITICAL


def test_divide_with_guard_no_flag(analyzer, config):
    """Division with guard condition should not be flagged."""
    code = """
def calc(x, y):
    if y != 0:
        return x / y
    return None
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    div_zero = [f for f in findings if "CWE-369" in f.message]
    assert len(div_zero) == 0


def test_divide_by_literal_no_flag(analyzer, config):
    """Division by non-zero literal should not be flagged."""
    code = """
def calc(x):
    return x / 5
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    div_zero = [f for f in findings if "CWE-369" in f.message]
    assert len(div_zero) == 0


def test_divide_by_zero_disabled(analyzer):
    """Divide by zero should not be checked if disabled."""
    config = Config(check_divide_by_zero=False)
    code = """
def calc(x, y):
    return x / y
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    div_zero = [f for f in findings if "CWE-369" in f.message]
    assert len(div_zero) == 0


# ============================================================================
# CWE-248: Uncaught Exception Tests (opt-in)
# ============================================================================


def test_uncaught_exception_disabled_by_default(analyzer, config):
    """Uncaught exceptions should not be checked by default."""
    code = """
def func():
    raise ValueError("error")
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    uncaught = [f for f in findings if "CWE-248" in f.message]
    assert len(uncaught) == 0


def test_uncaught_exception_when_enabled(analyzer):
    """Uncaught exceptions should be detected when enabled."""
    config = Config(check_uncaught_exceptions=True)
    code = """
def func():
    raise ValueError("error")
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    uncaught = [f for f in findings if "CWE-248" in f.message]
    assert len(uncaught) == 1
    assert uncaught[0].severity == Severity.LOW


# ============================================================================
# CWE-252: Unchecked Return Value Tests (opt-in)
# ============================================================================


def test_unchecked_return_disabled_by_default(analyzer, config):
    """Unchecked returns should not be checked by default."""
    code = """
some_function()
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    unchecked = [f for f in findings if "CWE-252" in f.message]
    assert len(unchecked) == 0


def test_unchecked_return_when_enabled(analyzer):
    """Unchecked returns should be detected when enabled."""
    config = Config(check_unchecked_returns=True)
    code = """
some_function()
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    unchecked = [f for f in findings if "CWE-252" in f.message]
    assert len(unchecked) == 1
    assert unchecked[0].severity == Severity.LOW


def test_unchecked_return_side_effect_functions_ignored(analyzer):
    """Side-effect functions should not be flagged."""
    config = Config(check_unchecked_returns=True)
    code = """
print("hello")
list.append(1)
"""
    tree = parse_python(code)
    findings = analyzer.analyze("test.py", code, tree, config)

    unchecked = [f for f in findings if "CWE-252" in f.message]
    assert len(unchecked) == 0


# ============================================================================
# Integration Tests
# ============================================================================


def test_fixture_file_analysis(analyzer, config):
    """Test analysis on the comprehensive fixture file."""
    fixture_path = Path(__file__).parent / "fixtures" / "exception_patterns.py"
    source = fixture_path.read_text()
    tree = parse_python(source)
    findings = analyzer.analyze(str(fixture_path), source, tree, config)

    # Should find multiple issues
    assert len(findings) > 0

    # Check for each CWE type (default config)
    bare_excepts = [f for f in findings if "Bare except" in f.message]
    assert len(bare_excepts) > 0

    resource_leaks = [f for f in findings if "CWE-772" in f.message]
    assert len(resource_leaks) > 0

    float_comps = [f for f in findings if "CWE-1077" in f.message]
    assert len(float_comps) > 0

    obj_comps = [f for f in findings if "CWE-595" in f.message]
    assert len(obj_comps) > 0

    div_zero = [f for f in findings if "CWE-369" in f.message]
    assert len(div_zero) > 0


def test_all_findings_have_correct_type(analyzer, config):
    """All findings should have DebtType.EXCEPTION."""
    fixture_path = Path(__file__).parent / "fixtures" / "exception_patterns.py"
    source = fixture_path.read_text()
    tree = parse_python(source)
    findings = analyzer.analyze(str(fixture_path), source, tree, config)

    for finding in findings:
        assert finding.debt_type == DebtType.EXCEPTION


def test_all_findings_have_remediation_time(analyzer, config):
    """All findings should have remediation time > 0."""
    fixture_path = Path(__file__).parent / "fixtures" / "exception_patterns.py"
    source = fixture_path.read_text()
    tree = parse_python(source)
    findings = analyzer.analyze(str(fixture_path), source, tree, config)

    for finding in findings:
        assert finding.remediation_minutes > 0
