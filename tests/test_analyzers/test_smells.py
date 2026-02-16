from tech_debtor.analyzers.smells import SmellAnalyzer
from tech_debtor.analyzers.base import parse_python
from tech_debtor.config import Config
from tech_debtor.models import DebtType


LONG_FUNCTION = "def f():\n" + "    x = 1\n" * 60

DEEP_NESTING = """
def f():
    if True:
        if True:
            if True:
                if True:
                    if True:
                        pass
"""

MANY_PARAMS = """
def f(a, b, c, d, e, f, g, h):
    pass
"""

GOD_CLASS = "class Huge:\n" + "".join(
    f"    def method_{i}(self):\n        pass\n" for i in range(25)
)

CLEAN_CODE = """
def clean(x, y):
    return x + y
"""


def test_long_function():
    analyzer = SmellAnalyzer()
    tree = parse_python(LONG_FUNCTION)
    findings = analyzer.analyze(
        "t.py", LONG_FUNCTION, tree, Config(max_function_length=50)
    )
    assert len(findings) == 1
    assert findings[0].debt_type == DebtType.SMELL
    assert "Long function" in findings[0].message


def test_deep_nesting():
    analyzer = SmellAnalyzer()
    tree = parse_python(DEEP_NESTING)
    findings = analyzer.analyze("t.py", DEEP_NESTING, tree, Config(max_nesting_depth=3))
    assert len(findings) == 1
    assert "nesting" in findings[0].message.lower()


def test_many_parameters():
    analyzer = SmellAnalyzer()
    tree = parse_python(MANY_PARAMS)
    findings = analyzer.analyze("t.py", MANY_PARAMS, tree, Config(max_parameters=5))
    assert len(findings) == 1
    assert "parameter" in findings[0].message.lower()


def test_god_class():
    analyzer = SmellAnalyzer()
    tree = parse_python(GOD_CLASS)
    findings = analyzer.analyze("t.py", GOD_CLASS, tree, Config())
    assert any("God class" in f.message or "methods" in f.message for f in findings)


def test_clean_code_no_findings():
    analyzer = SmellAnalyzer()
    tree = parse_python(CLEAN_CODE)
    findings = analyzer.analyze("t.py", CLEAN_CODE, tree, Config())
    assert len(findings) == 0
