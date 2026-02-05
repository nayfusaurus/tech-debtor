from tech_debtor.analyzers.duplication import DuplicationAnalyzer
from tech_debtor.analyzers.base import parse_python
from tech_debtor.config import Config
from tech_debtor.models import DebtType


DUPLICATED = """
def process_a(items):
    result = []
    for item in items:
        if item.active:
            result.append(item.value * 2)
    return result

def process_b(items):
    result = []
    for item in items:
        if item.active:
            result.append(item.value * 2)
    return result
"""

NO_DUPLICATES = """
def add(x, y):
    return x + y

def multiply(x, y):
    return x * y
"""


def test_detects_duplication():
    analyzer = DuplicationAnalyzer()
    tree = parse_python(DUPLICATED)
    findings = analyzer.analyze("t.py", DUPLICATED, tree, Config())
    assert len(findings) >= 1
    assert all(f.debt_type == DebtType.DUPLICATION for f in findings)


def test_no_false_positives():
    analyzer = DuplicationAnalyzer()
    tree = parse_python(NO_DUPLICATES)
    findings = analyzer.analyze("t.py", NO_DUPLICATES, tree, Config())
    assert len(findings) == 0
