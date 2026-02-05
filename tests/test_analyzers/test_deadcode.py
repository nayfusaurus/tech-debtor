from tech_debtor.analyzers.deadcode import DeadCodeAnalyzer
from tech_debtor.analyzers.base import parse_python
from tech_debtor.config import Config
from tech_debtor.models import DebtType


UNUSED_IMPORT = """
import os
import sys

def main():
    print(sys.argv)
"""

UNUSED_FUNCTION = """
def used():
    return 1

def unused():
    return 2

result = used()
"""

ALL_USED = """
import os

def helper():
    return os.getcwd()

result = helper()
"""


def test_unused_import():
    analyzer = DeadCodeAnalyzer()
    tree = parse_python(UNUSED_IMPORT)
    findings = analyzer.analyze("t.py", UNUSED_IMPORT, tree, Config())
    assert len(findings) == 1
    assert findings[0].debt_type == DebtType.DEAD_CODE
    assert "os" in findings[0].message


def test_unused_function():
    analyzer = DeadCodeAnalyzer()
    tree = parse_python(UNUSED_FUNCTION)
    findings = analyzer.analyze("t.py", UNUSED_FUNCTION, tree, Config())
    assert any("unused" in f.message.lower() for f in findings)


def test_all_used_no_findings():
    analyzer = DeadCodeAnalyzer()
    tree = parse_python(ALL_USED)
    findings = analyzer.analyze("t.py", ALL_USED, tree, Config())
    assert len(findings) == 0
