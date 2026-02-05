from tech_debtor.analyzers.complexity import ComplexityAnalyzer
from tech_debtor.analyzers.base import parse_python
from tech_debtor.config import Config
from tech_debtor.models import Severity, DebtType


SIMPLE_FUNCTION = """
def add(x, y):
    return x + y
"""

COMPLEX_FUNCTION = """
def process(data):
    if data is None:
        return None
    result = []
    for item in data:
        if item.active:
            if item.value > 100:
                if item.category == "A":
                    result.append(item.value * 2)
                elif item.category == "B":
                    result.append(item.value * 3)
                else:
                    result.append(item.value)
            else:
                result.append(item.value)
        else:
            for sub in item.children:
                if sub.valid:
                    result.append(sub.value)
    return result
"""


def test_simple_function_no_findings():
    analyzer = ComplexityAnalyzer()
    tree = parse_python(SIMPLE_FUNCTION)
    cfg = Config(max_complexity=10, max_cognitive_complexity=10)
    findings = analyzer.analyze("test.py", SIMPLE_FUNCTION, tree, cfg)
    assert len(findings) == 0


def test_complex_function_flagged():
    analyzer = ComplexityAnalyzer()
    tree = parse_python(COMPLEX_FUNCTION)
    cfg = Config(max_complexity=5, max_cognitive_complexity=5)
    findings = analyzer.analyze("test.py", COMPLEX_FUNCTION, tree, cfg)
    assert len(findings) > 0
    assert all(f.debt_type == DebtType.COMPLEXITY for f in findings)
    assert any(f.severity >= Severity.HIGH for f in findings)
    assert all("process" in f.symbol for f in findings if f.symbol)


def test_cyclomatic_complexity_counts_branches():
    analyzer = ComplexityAnalyzer()
    tree = parse_python(COMPLEX_FUNCTION)
    cfg = Config(max_complexity=1)
    findings = analyzer.analyze("test.py", COMPLEX_FUNCTION, tree, cfg)
    cyc_findings = [f for f in findings if "Cyclomatic" in f.message]
    assert len(cyc_findings) == 1
    msg = cyc_findings[0].message
    complexity_val = int(msg.split(":")[1].strip().split(" ")[0])
    assert complexity_val >= 8
