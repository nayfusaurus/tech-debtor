# tech-debtor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a CLI tool that analyzes Python projects for code-level technical debt (complexity, smells, duplication, dead code, git churn) and produces prioritized, actionable reports.

**Architecture:** tree-sitter parses Python files into ASTs. Pluggable analyzers each walk the AST looking for one debt type. A scorer aggregates findings into a 0-100 debt score. Reporters render output as rich terminal or JSON.

**Tech Stack:** Python 3.12+, uv, tree-sitter + tree-sitter-python, rich, click, gitpython, pytest, ruff

---

### Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `src/tech_debtor/__init__.py`

**Step 1: Initialize uv project**

```bash
cd /home/yan/Projects/tech-debtor
uv init --lib --name tech-debtor
```

This creates `pyproject.toml` and `src/tech_debtor/__init__.py`.

**Step 2: Configure pyproject.toml**

Edit `pyproject.toml` to set the project metadata, Python version, and console script entry point:

```toml
[project]
name = "tech-debtor"
version = "0.1.0"
description = "Python technical debt analyzer"
requires-python = ">=3.12"
dependencies = [
    "tree-sitter>=0.23",
    "tree-sitter-python>=0.23",
    "rich>=13.0",
    "click>=8.0",
    "gitpython>=3.1",
]

[project.scripts]
tech-debtor = "tech_debtor.cli:main"

[tool.tech-debtor]
max-complexity = 15
max-cognitive-complexity = 10
max-function-length = 50
max-parameters = 5
max-nesting-depth = 4
min-severity = "medium"
exclude = ["tests/", "migrations/"]
cost-per-line = 0.5
```

**Step 3: Add dev dependencies**

```bash
uv add --dev pytest ruff mypy
```

**Step 4: Create package init**

Write `src/tech_debtor/__init__.py`:

```python
"""tech-debtor: Python technical debt analyzer."""

__version__ = "0.1.0"
```

**Step 5: Verify setup**

```bash
uv sync
uv run python -c "import tech_debtor; print(tech_debtor.__version__)"
```

Expected: `0.1.0`

**Step 6: Commit**

```bash
git add pyproject.toml src/ uv.lock
git commit -m "feat: initialize tech-debtor project with uv"
```

---

### Task 2: Data Models

**Files:**
- Create: `src/tech_debtor/models.py`
- Create: `tests/test_models.py`

**Step 1: Write the failing test**

Create `tests/test_models.py`:

```python
from tech_debtor.models import Finding, Severity, DebtType, FileReport, ProjectReport


def test_finding_creation():
    f = Finding(
        file_path="src/foo.py",
        line=10,
        end_line=25,
        debt_type=DebtType.COMPLEXITY,
        severity=Severity.HIGH,
        message="Cyclomatic complexity: 18 (threshold: 10)",
        suggestion="Break into smaller functions",
        remediation_minutes=45,
        symbol="process_payment",
    )
    assert f.severity == Severity.HIGH
    assert f.remediation_minutes == 45
    assert f.debt_type == DebtType.COMPLEXITY


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW


def test_file_report_aggregation():
    findings = [
        Finding(
            file_path="a.py",
            line=1,
            end_line=10,
            debt_type=DebtType.COMPLEXITY,
            severity=Severity.HIGH,
            message="Complex",
            suggestion="Simplify",
            remediation_minutes=30,
        ),
        Finding(
            file_path="a.py",
            line=20,
            end_line=25,
            debt_type=DebtType.DEAD_CODE,
            severity=Severity.LOW,
            message="Unused",
            suggestion="Remove",
            remediation_minutes=5,
        ),
    ]
    report = FileReport(file_path="a.py", lines_of_code=100, findings=findings)
    assert report.total_remediation_minutes == 35
    assert report.finding_count == 2


def test_project_report_debt_score():
    finding = Finding(
        file_path="a.py",
        line=1,
        end_line=10,
        debt_type=DebtType.COMPLEXITY,
        severity=Severity.HIGH,
        message="Complex",
        suggestion="Simplify",
        remediation_minutes=30,
    )
    file_report = FileReport(file_path="a.py", lines_of_code=100, findings=[finding])
    project = ProjectReport(file_reports=[file_report], cost_per_line=0.5)
    # debt_score = min(100, (30 / (100 * 0.5)) * 100) = min(100, 60) = 60
    assert project.debt_score == 60
    assert project.total_files == 1
    assert project.total_findings == 1
    assert project.debt_rating == "Fair"
```

**Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_models.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'tech_debtor.models'`

**Step 3: Write minimal implementation**

Create `src/tech_debtor/models.py`:

```python
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class DebtType(StrEnum):
    COMPLEXITY = "complexity"
    SMELL = "smell"
    DUPLICATION = "duplication"
    DEAD_CODE = "dead_code"
    CHURN = "churn"


@dataclass(frozen=True)
class Finding:
    file_path: str
    line: int
    end_line: int
    debt_type: DebtType
    severity: Severity
    message: str
    suggestion: str
    remediation_minutes: int
    symbol: str | None = None


@dataclass
class FileReport:
    file_path: str
    lines_of_code: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def total_remediation_minutes(self) -> int:
        return sum(f.remediation_minutes for f in self.findings)

    @property
    def finding_count(self) -> int:
        return len(self.findings)


@dataclass
class ProjectReport:
    file_reports: list[FileReport] = field(default_factory=list)
    cost_per_line: float = 0.5

    @property
    def all_findings(self) -> list[Finding]:
        return [f for r in self.file_reports for f in r.findings]

    @property
    def total_lines(self) -> int:
        return sum(r.lines_of_code for r in self.file_reports)

    @property
    def total_remediation_minutes(self) -> int:
        return sum(r.total_remediation_minutes for r in self.file_reports)

    @property
    def total_files(self) -> int:
        return len(self.file_reports)

    @property
    def total_findings(self) -> int:
        return sum(r.finding_count for r in self.file_reports)

    @property
    def debt_score(self) -> int:
        if self.total_lines == 0:
            return 0
        raw = (self.total_remediation_minutes / (self.total_lines * self.cost_per_line)) * 100
        return min(100, int(raw))

    @property
    def debt_rating(self) -> str:
        score = self.debt_score
        if score <= 20:
            return "Excellent"
        if score <= 40:
            return "Good"
        if score <= 60:
            return "Fair"
        if score <= 80:
            return "Poor"
        return "Critical"
```

**Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_models.py -v
```

Expected: all 4 tests PASS

**Step 5: Commit**

```bash
git add src/tech_debtor/models.py tests/test_models.py
git commit -m "feat: add data models (Finding, FileReport, ProjectReport)"
```

---

### Task 3: Config Loading

**Files:**
- Create: `src/tech_debtor/config.py`
- Create: `tests/test_config.py`

**Step 1: Write the failing test**

Create `tests/test_config.py`:

```python
from pathlib import Path
from tech_debtor.config import Config, load_config


def test_default_config():
    cfg = Config()
    assert cfg.max_complexity == 15
    assert cfg.max_cognitive_complexity == 10
    assert cfg.max_function_length == 50
    assert cfg.max_parameters == 5
    assert cfg.max_nesting_depth == 4
    assert cfg.min_severity == "medium"
    assert cfg.exclude == []
    assert cfg.cost_per_line == 0.5


def test_load_config_from_pyproject(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("""
[tool.tech-debtor]
max-complexity = 20
max-function-length = 100
exclude = ["vendor/"]
""")
    cfg = load_config(tmp_path)
    assert cfg.max_complexity == 20
    assert cfg.max_function_length == 100
    assert cfg.exclude == ["vendor/"]
    # Defaults still apply for unset values
    assert cfg.max_parameters == 5


def test_load_config_missing_file(tmp_path):
    cfg = load_config(tmp_path)
    assert cfg.max_complexity == 15  # all defaults
```

**Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_config.py -v
```

Expected: FAIL — `ModuleNotFoundError`

**Step 3: Write minimal implementation**

Create `src/tech_debtor/config.py`:

```python
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None  # type: ignore[assignment]


@dataclass
class Config:
    max_complexity: int = 15
    max_cognitive_complexity: int = 10
    max_function_length: int = 50
    max_parameters: int = 5
    max_nesting_depth: int = 4
    min_severity: str = "medium"
    exclude: list[str] = field(default_factory=list)
    cost_per_line: float = 0.5


def load_config(project_path: Path) -> Config:
    pyproject = project_path / "pyproject.toml"
    if not pyproject.exists():
        return Config()

    if tomllib is None:
        return Config()

    with open(pyproject, "rb") as f:
        data = tomllib.load(f)

    tool_config = data.get("tool", {}).get("tech-debtor", {})
    if not tool_config:
        return Config()

    field_map = {
        "max-complexity": "max_complexity",
        "max-cognitive-complexity": "max_cognitive_complexity",
        "max-function-length": "max_function_length",
        "max-parameters": "max_parameters",
        "max-nesting-depth": "max_nesting_depth",
        "min-severity": "min_severity",
        "exclude": "exclude",
        "cost-per-line": "cost_per_line",
    }

    kwargs = {}
    for toml_key, attr_name in field_map.items():
        if toml_key in tool_config:
            kwargs[attr_name] = tool_config[toml_key]

    return Config(**kwargs)
```

**Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_config.py -v
```

Expected: all 3 tests PASS

**Step 5: Commit**

```bash
git add src/tech_debtor/config.py tests/test_config.py
git commit -m "feat: add config loading from pyproject.toml"
```

---

### Task 4: File Scanner

**Files:**
- Create: `src/tech_debtor/scanner.py`
- Create: `tests/test_scanner.py`

**Step 1: Write the failing test**

Create `tests/test_scanner.py`:

```python
from pathlib import Path
from tech_debtor.scanner import scan_python_files


def test_finds_python_files(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    (tmp_path / "b.py").write_text("y = 2")
    (tmp_path / "c.txt").write_text("not python")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "d.py").write_text("z = 3")

    files = list(scan_python_files(tmp_path, exclude=[]))
    assert len(files) == 3
    names = {f.name for f in files}
    assert names == {"a.py", "b.py", "d.py"}


def test_excludes_patterns(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "b.py").write_text("y = 2")

    files = list(scan_python_files(tmp_path, exclude=["migrations/"]))
    assert len(files) == 1
    assert files[0].name == "a.py"


def test_excludes_hidden_and_venv(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "b.py").write_text("y = 2")
    dot = tmp_path / ".hidden"
    dot.mkdir()
    (dot / "c.py").write_text("z = 3")

    files = list(scan_python_files(tmp_path, exclude=[]))
    assert len(files) == 1
```

**Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_scanner.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

Create `src/tech_debtor/scanner.py`:

```python
from __future__ import annotations

from pathlib import Path
from typing import Iterator

ALWAYS_EXCLUDE = {".venv", "venv", ".git", "__pycache__", ".mypy_cache", ".ruff_cache", "node_modules", ".tox", ".eggs", "*.egg-info"}


def _is_excluded(path: Path, root: Path, exclude: list[str]) -> bool:
    rel = path.relative_to(root)
    for part in rel.parts:
        if part.startswith(".") or part in ALWAYS_EXCLUDE or part.endswith(".egg-info"):
            return True
    for pattern in exclude:
        pattern_clean = pattern.rstrip("/")
        if any(part == pattern_clean for part in rel.parts):
            return True
    return False


def scan_python_files(root: Path, exclude: list[str]) -> Iterator[Path]:
    for path in sorted(root.rglob("*.py")):
        if not path.is_file():
            continue
        if _is_excluded(path, root, exclude):
            continue
        yield path
```

**Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_scanner.py -v
```

Expected: all 3 tests PASS

**Step 5: Commit**

```bash
git add src/tech_debtor/scanner.py tests/test_scanner.py
git commit -m "feat: add file scanner with exclusion support"
```

---

### Task 5: Base Analyzer Protocol and tree-sitter Parser

**Files:**
- Create: `src/tech_debtor/analyzers/__init__.py`
- Create: `src/tech_debtor/analyzers/base.py`
- Create: `tests/test_analyzers/__init__.py`
- Create: `tests/test_analyzers/test_base.py`

**Step 1: Write the failing test**

Create `tests/test_analyzers/__init__.py` (empty) and `tests/test_analyzers/test_base.py`:

```python
from tech_debtor.analyzers.base import parse_python, tree_to_functions, tree_to_classes


CODE = """
def foo(x, y):
    return x + y

class Bar:
    def method(self):
        pass

def baz():
    if True:
        for i in range(10):
            pass
"""


def test_parse_python():
    tree = parse_python(CODE)
    assert tree is not None
    assert tree.root_node.type == "module"


def test_tree_to_functions():
    tree = parse_python(CODE)
    funcs = tree_to_functions(tree.root_node)
    names = [f.child_by_field_name("name").text.decode() for f in funcs]
    assert "foo" in names
    assert "baz" in names
    assert "method" in names


def test_tree_to_classes():
    tree = parse_python(CODE)
    classes = tree_to_classes(tree.root_node)
    names = [c.child_by_field_name("name").text.decode() for c in classes]
    assert names == ["Bar"]
```

**Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_analyzers/test_base.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

Create `src/tech_debtor/analyzers/__init__.py` (empty) and `src/tech_debtor/analyzers/base.py`:

```python
from __future__ import annotations

from typing import Protocol

from tree_sitter import Language, Parser, Tree, Node
import tree_sitter_python as tspython

from tech_debtor.config import Config
from tech_debtor.models import Finding

PY_LANGUAGE = Language(tspython.language())


def parse_python(source: str) -> Tree:
    parser = Parser(PY_LANGUAGE)
    return parser.parse(bytes(source, "utf-8"))


def _find_nodes(node: Node, target_type: str) -> list[Node]:
    results = []
    if node.type == target_type:
        results.append(node)
    for child in node.children:
        results.extend(_find_nodes(child, target_type))
    return results


def tree_to_functions(root: Node) -> list[Node]:
    return _find_nodes(root, "function_definition")


def tree_to_classes(root: Node) -> list[Node]:
    return _find_nodes(root, "class_definition")


class Analyzer(Protocol):
    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]: ...
```

**Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_analyzers/test_base.py -v
```

Expected: all 3 tests PASS

**Step 5: Commit**

```bash
git add src/tech_debtor/analyzers/ tests/test_analyzers/
git commit -m "feat: add base analyzer protocol and tree-sitter parser helpers"
```

---

### Task 6: Complexity Analyzer

**Files:**
- Create: `src/tech_debtor/analyzers/complexity.py`
- Create: `tests/test_analyzers/test_complexity.py`

**Step 1: Write the failing test**

Create `tests/test_analyzers/test_complexity.py`:

```python
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
    """Each if/elif/for/while/except/and/or adds 1 to cyclomatic complexity."""
    analyzer = ComplexityAnalyzer()
    tree = parse_python(COMPLEX_FUNCTION)
    cfg = Config(max_complexity=1)  # Very low threshold to ensure it triggers
    findings = analyzer.analyze("test.py", COMPLEX_FUNCTION, tree, cfg)
    cyc_findings = [f for f in findings if "Cyclomatic" in f.message]
    assert len(cyc_findings) == 1
    # Parse out the number from "Cyclomatic complexity: N"
    msg = cyc_findings[0].message
    complexity_val = int(msg.split(":")[1].strip().split(" ")[0])
    assert complexity_val >= 8  # multiple branches
```

**Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_analyzers/test_complexity.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

Create `src/tech_debtor/analyzers/complexity.py`:

```python
from __future__ import annotations

from tree_sitter import Tree, Node

from tech_debtor.analyzers.base import tree_to_functions
from tech_debtor.config import Config
from tech_debtor.models import DebtType, Finding, Severity

# Node types that add 1 to cyclomatic complexity
CYCLOMATIC_BRANCH_TYPES = {
    "if_statement",
    "elif_clause",
    "for_statement",
    "while_statement",
    "except_clause",
    "with_statement",
    "assert_statement",
}

BOOLEAN_OPERATORS = {"and", "or"}

# Node types that add to cognitive complexity with nesting penalty
COGNITIVE_INCREMENT_TYPES = {
    "if_statement",
    "for_statement",
    "while_statement",
    "except_clause",
}

COGNITIVE_NO_NESTING_TYPES = {
    "elif_clause",
    "else_clause",
}


def _count_nodes(node: Node, target_types: set[str]) -> int:
    count = 0
    if node.type in target_types:
        count += 1
    for child in node.children:
        count += _count_nodes(child, target_types)
    return count


def _count_boolean_operators(node: Node) -> int:
    count = 0
    if node.type == "boolean_operator":
        count += 1
    for child in node.children:
        count += _count_boolean_operators(child)
    return count


def _cognitive_complexity(node: Node, nesting: int = 0) -> int:
    total = 0
    for child in node.children:
        if child.type in COGNITIVE_INCREMENT_TYPES:
            total += 1 + nesting
            total += _cognitive_complexity(child, nesting + 1)
        elif child.type in COGNITIVE_NO_NESTING_TYPES:
            total += 1
            total += _cognitive_complexity(child, nesting)
        elif child.type == "boolean_operator":
            total += 1
            total += _cognitive_complexity(child, nesting)
        else:
            total += _cognitive_complexity(child, nesting)
    return total


def _func_name(func_node: Node) -> str:
    name_node = func_node.child_by_field_name("name")
    return name_node.text.decode() if name_node else "<anonymous>"


def _severity_for_excess(excess: int, threshold: int) -> Severity:
    ratio = excess / max(threshold, 1)
    if ratio >= 2.0:
        return Severity.CRITICAL
    if ratio >= 1.0:
        return Severity.HIGH
    if ratio >= 0.5:
        return Severity.MEDIUM
    return Severity.LOW


def _remediation_minutes(excess: int) -> int:
    return max(5, excess * 5)


class ComplexityAnalyzer:
    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        functions = tree_to_functions(tree.root_node)

        for func in functions:
            name = _func_name(func)
            body = func.child_by_field_name("body")
            if body is None:
                continue

            # Cyclomatic complexity: 1 (baseline) + branches + boolean ops
            branches = _count_nodes(body, CYCLOMATIC_BRANCH_TYPES)
            bool_ops = _count_boolean_operators(body)
            cyclomatic = 1 + branches + bool_ops

            if cyclomatic > config.max_complexity:
                excess = cyclomatic - config.max_complexity
                findings.append(Finding(
                    file_path=file_path,
                    line=func.start_point[0] + 1,
                    end_line=func.end_point[0] + 1,
                    debt_type=DebtType.COMPLEXITY,
                    severity=_severity_for_excess(excess, config.max_complexity),
                    message=f"Cyclomatic complexity: {cyclomatic} (threshold: {config.max_complexity})",
                    suggestion="Break into smaller functions, extract conditional logic",
                    remediation_minutes=_remediation_minutes(excess),
                    symbol=name,
                ))

            # Cognitive complexity
            cognitive = _cognitive_complexity(body)

            if cognitive > config.max_cognitive_complexity:
                excess = cognitive - config.max_cognitive_complexity
                findings.append(Finding(
                    file_path=file_path,
                    line=func.start_point[0] + 1,
                    end_line=func.end_point[0] + 1,
                    debt_type=DebtType.COMPLEXITY,
                    severity=_severity_for_excess(excess, config.max_cognitive_complexity),
                    message=f"Cognitive complexity: {cognitive} (threshold: {config.max_cognitive_complexity})",
                    suggestion="Reduce nesting depth, extract helper functions, simplify conditionals",
                    remediation_minutes=_remediation_minutes(excess),
                    symbol=name,
                ))

        return findings
```

**Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_analyzers/test_complexity.py -v
```

Expected: all 3 tests PASS

**Step 5: Commit**

```bash
git add src/tech_debtor/analyzers/complexity.py tests/test_analyzers/test_complexity.py
git commit -m "feat: add complexity analyzer (cyclomatic + cognitive)"
```

---

### Task 7: Code Smells Analyzer

**Files:**
- Create: `src/tech_debtor/analyzers/smells.py`
- Create: `tests/test_analyzers/test_smells.py`

**Step 1: Write the failing test**

Create `tests/test_analyzers/test_smells.py`:

```python
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
    findings = analyzer.analyze("t.py", LONG_FUNCTION, tree, Config(max_function_length=50))
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
```

**Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_analyzers/test_smells.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

Create `src/tech_debtor/analyzers/smells.py`:

```python
from __future__ import annotations

from tree_sitter import Tree, Node

from tech_debtor.analyzers.base import tree_to_functions, tree_to_classes, _find_nodes
from tech_debtor.config import Config
from tech_debtor.models import DebtType, Finding, Severity

GOD_CLASS_METHOD_THRESHOLD = 20


def _func_name(node: Node) -> str:
    name_node = node.child_by_field_name("name")
    return name_node.text.decode() if name_node else "<anonymous>"


def _class_name(node: Node) -> str:
    name_node = node.child_by_field_name("name")
    return name_node.text.decode() if name_node else "<anonymous>"


def _function_length(func_node: Node) -> int:
    return func_node.end_point[0] - func_node.start_point[0]


def _max_nesting_depth(node: Node, current: int = 0) -> int:
    nesting_types = {"if_statement", "for_statement", "while_statement", "with_statement", "try_statement"}
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
    # Count identifier children in parameters, excluding 'self' and 'cls'
    count = 0
    for child in params.named_children:
        if child.type in ("identifier", "typed_parameter", "default_parameter",
                          "typed_default_parameter", "list_splat_pattern",
                          "dictionary_splat_pattern"):
            text = child.text.decode()
            if text not in ("self", "cls"):
                count += 1
    return count


class SmellAnalyzer:
    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        functions = tree_to_functions(tree.root_node)

        for func in functions:
            name = _func_name(func)
            line = func.start_point[0] + 1
            end_line = func.end_point[0] + 1

            # Long function
            length = _function_length(func)
            if length > config.max_function_length:
                excess = length - config.max_function_length
                findings.append(Finding(
                    file_path=file_path,
                    line=line,
                    end_line=end_line,
                    debt_type=DebtType.SMELL,
                    severity=Severity.HIGH if excess > config.max_function_length else Severity.MEDIUM,
                    message=f"Long function: {length} lines (threshold: {config.max_function_length})",
                    suggestion="Extract logic into smaller, focused functions",
                    remediation_minutes=max(5, excess * 2),
                    symbol=name,
                ))

            # Deep nesting
            body = func.child_by_field_name("body")
            if body:
                depth = _max_nesting_depth(body)
                if depth > config.max_nesting_depth:
                    findings.append(Finding(
                        file_path=file_path,
                        line=line,
                        end_line=end_line,
                        debt_type=DebtType.SMELL,
                        severity=Severity.HIGH if depth > config.max_nesting_depth + 2 else Severity.MEDIUM,
                        message=f"Deep nesting: depth {depth} (threshold: {config.max_nesting_depth})",
                        suggestion="Use early returns, extract nested logic into functions",
                        remediation_minutes=max(5, (depth - config.max_nesting_depth) * 10),
                        symbol=name,
                    ))

            # Too many parameters
            param_count = _param_count(func)
            if param_count > config.max_parameters:
                findings.append(Finding(
                    file_path=file_path,
                    line=line,
                    end_line=end_line,
                    debt_type=DebtType.SMELL,
                    severity=Severity.MEDIUM,
                    message=f"Too many parameters: {param_count} (threshold: {config.max_parameters})",
                    suggestion="Group parameters into a dataclass or configuration object",
                    remediation_minutes=max(5, (param_count - config.max_parameters) * 5),
                    symbol=name,
                ))

        # God classes
        classes = tree_to_classes(tree.root_node)
        for cls in classes:
            cls_name = _class_name(cls)
            methods = _find_nodes(cls, "function_definition")
            method_count = len(methods)
            if method_count > GOD_CLASS_METHOD_THRESHOLD:
                findings.append(Finding(
                    file_path=file_path,
                    line=cls.start_point[0] + 1,
                    end_line=cls.end_point[0] + 1,
                    debt_type=DebtType.SMELL,
                    severity=Severity.HIGH,
                    message=f"God class: {method_count} methods (threshold: {GOD_CLASS_METHOD_THRESHOLD})",
                    suggestion="Split into focused classes using single-responsibility principle",
                    remediation_minutes=method_count * 5,
                    symbol=cls_name,
                ))

        return findings
```

**Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_analyzers/test_smells.py -v
```

Expected: all 5 tests PASS

**Step 5: Commit**

```bash
git add src/tech_debtor/analyzers/smells.py tests/test_analyzers/test_smells.py
git commit -m "feat: add code smells analyzer (long functions, deep nesting, params, god classes)"
```

---

### Task 8: Dead Code Analyzer

**Files:**
- Create: `src/tech_debtor/analyzers/deadcode.py`
- Create: `tests/test_analyzers/test_deadcode.py`

**Step 1: Write the failing test**

Create `tests/test_analyzers/test_deadcode.py`:

```python
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
```

**Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_analyzers/test_deadcode.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

Create `src/tech_debtor/analyzers/deadcode.py`:

```python
from __future__ import annotations

import re

from tree_sitter import Tree, Node

from tech_debtor.analyzers.base import tree_to_functions, _find_nodes
from tech_debtor.config import Config
from tech_debtor.models import DebtType, Finding, Severity


def _get_imported_names(root: Node) -> list[tuple[str, Node]]:
    """Get all imported names and their nodes."""
    names = []
    for node in root.children:
        if node.type == "import_statement":
            for child in node.named_children:
                if child.type == "dotted_name":
                    # import foo -> just the first part is used as identifier
                    first = child.named_children[0] if child.named_children else child
                    names.append((first.text.decode(), node))
        elif node.type == "import_from_statement":
            for child in node.named_children:
                if child.type == "dotted_name" and child != node.named_children[0]:
                    names.append((child.text.decode(), node))
                elif child.type == "aliased_import":
                    alias = child.child_by_field_name("alias")
                    name_node = child.child_by_field_name("name")
                    if alias:
                        names.append((alias.text.decode(), node))
                    elif name_node:
                        names.append((name_node.text.decode(), node))
    return names


def _get_all_identifiers(node: Node) -> set[str]:
    """Collect all identifier names used in the AST (not in import statements)."""
    ids: set[str] = set()
    if node.type == "import_statement" or node.type == "import_from_statement":
        return ids
    if node.type == "identifier":
        ids.add(node.text.decode())
    for child in node.children:
        ids.update(_get_all_identifiers(child))
    return ids


def _get_top_level_functions(root: Node) -> list[Node]:
    """Get functions defined at module level only."""
    return [n for n in root.children if n.type == "function_definition"]


def _func_name(node: Node) -> str:
    name_node = node.child_by_field_name("name")
    return name_node.text.decode() if name_node else "<anonymous>"


class DeadCodeAnalyzer:
    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        root = tree.root_node

        # Collect all identifiers used in non-import code
        all_ids = set()
        for child in root.children:
            if child.type not in ("import_statement", "import_from_statement"):
                all_ids.update(_get_all_identifiers(child))

        # Check unused imports
        for name, node in _get_imported_names(root):
            if name not in all_ids:
                findings.append(Finding(
                    file_path=file_path,
                    line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    debt_type=DebtType.DEAD_CODE,
                    severity=Severity.LOW,
                    message=f"Unused import: {name}",
                    suggestion="Remove unused import",
                    remediation_minutes=2,
                    symbol=name,
                ))

        # Check unused top-level functions
        # Collect identifiers excluding function definitions themselves
        usage_ids: set[str] = set()
        top_funcs = _get_top_level_functions(root)
        top_func_names = {_func_name(f) for f in top_funcs}

        for child in root.children:
            if child.type == "function_definition":
                # Collect identifiers used inside function bodies
                body = child.child_by_field_name("body")
                if body:
                    usage_ids.update(_get_all_identifiers(body))
            elif child.type not in ("import_statement", "import_from_statement"):
                usage_ids.update(_get_all_identifiers(child))

        for func in top_funcs:
            name = _func_name(func)
            # Skip dunder methods and private methods starting with _
            if name.startswith("_"):
                continue
            if name not in usage_ids:
                findings.append(Finding(
                    file_path=file_path,
                    line=func.start_point[0] + 1,
                    end_line=func.end_point[0] + 1,
                    debt_type=DebtType.DEAD_CODE,
                    severity=Severity.LOW,
                    message=f"Unused function: {name} (0 references in file)",
                    suggestion="Remove or verify if used dynamically or by external callers",
                    remediation_minutes=5,
                    symbol=name,
                ))

        return findings
```

**Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_analyzers/test_deadcode.py -v
```

Expected: all 3 tests PASS

**Step 5: Commit**

```bash
git add src/tech_debtor/analyzers/deadcode.py tests/test_analyzers/test_deadcode.py
git commit -m "feat: add dead code analyzer (unused imports and functions)"
```

---

### Task 9: Duplication Analyzer

**Files:**
- Create: `src/tech_debtor/analyzers/duplication.py`
- Create: `tests/test_analyzers/test_duplication.py`

**Step 1: Write the failing test**

Create `tests/test_analyzers/test_duplication.py`:

```python
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
```

**Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_analyzers/test_duplication.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

Create `src/tech_debtor/analyzers/duplication.py`:

```python
from __future__ import annotations

from tree_sitter import Tree, Node

from tech_debtor.analyzers.base import tree_to_functions
from tech_debtor.config import Config
from tech_debtor.models import DebtType, Finding, Severity

MIN_LINES_FOR_DUPLICATE = 4


def _normalize_tree(node: Node) -> str:
    """Create a structural fingerprint of an AST node, ignoring identifiers."""
    if node.child_count == 0:
        # Leaf node: use type only (ignore actual text like variable names)
        return node.type
    children = " ".join(_normalize_tree(c) for c in node.children)
    return f"({node.type} {children})"


def _func_name(node: Node) -> str:
    name_node = node.child_by_field_name("name")
    return name_node.text.decode() if name_node else "<anonymous>"


class DuplicationAnalyzer:
    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        functions = tree_to_functions(tree.root_node)

        # Only compare functions with meaningful body length
        candidates: list[tuple[Node, str]] = []
        for func in functions:
            length = func.end_point[0] - func.start_point[0]
            if length >= MIN_LINES_FOR_DUPLICATE:
                body = func.child_by_field_name("body")
                if body:
                    fingerprint = _normalize_tree(body)
                    candidates.append((func, fingerprint))

        # Find pairs with identical structural fingerprints
        seen: dict[str, list[Node]] = {}
        for func, fp in candidates:
            seen.setdefault(fp, []).append(func)

        reported: set[str] = set()
        for fp, funcs in seen.items():
            if len(funcs) < 2:
                continue
            names = [_func_name(f) for f in funcs]
            key = tuple(sorted(names))
            if key in reported:
                continue
            reported.add(key)

            first = funcs[0]
            length = first.end_point[0] - first.start_point[0]
            locations = ", ".join(
                f"{_func_name(f)} (line {f.start_point[0] + 1})" for f in funcs
            )
            findings.append(Finding(
                file_path=file_path,
                line=first.start_point[0] + 1,
                end_line=first.end_point[0] + 1,
                debt_type=DebtType.DUPLICATION,
                severity=Severity.HIGH if length > 15 else Severity.MEDIUM,
                message=f"Duplicate code blocks ({length} lines): {locations}",
                suggestion="Extract shared logic into a common function",
                remediation_minutes=max(10, length * 2),
                symbol=_func_name(first),
            ))

        return findings
```

**Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_analyzers/test_duplication.py -v
```

Expected: all 2 tests PASS

**Step 5: Commit**

```bash
git add src/tech_debtor/analyzers/duplication.py tests/test_analyzers/test_duplication.py
git commit -m "feat: add duplication analyzer using AST structural fingerprinting"
```

---

### Task 10: Churn Analyzer

**Files:**
- Create: `src/tech_debtor/analyzers/churn.py`
- Create: `tests/test_analyzers/test_churn.py`

**Step 1: Write the failing test**

Create `tests/test_analyzers/test_churn.py`:

```python
import subprocess
from pathlib import Path

from tech_debtor.analyzers.churn import ChurnAnalyzer, get_file_churn
from tech_debtor.config import Config


def _init_git_repo(tmp_path: Path):
    """Create a git repo with some history."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True)
    f = tmp_path / "a.py"
    for i in range(5):
        f.write_text(f"x = {i}\n")
        subprocess.run(["git", "add", "a.py"], cwd=tmp_path, capture_output=True)
        subprocess.run(["git", "commit", "-m", f"commit {i}"], cwd=tmp_path, capture_output=True)


def test_get_file_churn(tmp_path):
    _init_git_repo(tmp_path)
    churn = get_file_churn(tmp_path)
    assert "a.py" in churn
    assert churn["a.py"] == 5


def test_churn_no_git(tmp_path):
    churn = get_file_churn(tmp_path)
    assert churn == {}
```

**Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_analyzers/test_churn.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

Create `src/tech_debtor/analyzers/churn.py`:

```python
from __future__ import annotations

from pathlib import Path

from tree_sitter import Tree

from tech_debtor.config import Config
from tech_debtor.models import DebtType, Finding, Severity

try:
    from git import Repo, InvalidGitRepositoryError
except ImportError:
    Repo = None  # type: ignore[assignment, misc]
    InvalidGitRepositoryError = Exception  # type: ignore[assignment, misc]


def get_file_churn(project_path: Path, max_commits: int = 500) -> dict[str, int]:
    """Count how many commits touched each file."""
    if Repo is None:
        return {}
    try:
        repo = Repo(project_path, search_parent_directories=True)
    except InvalidGitRepositoryError:
        return {}

    churn: dict[str, int] = {}
    try:
        for commit in repo.iter_commits(max_count=max_commits):
            for path in commit.stats.files:
                if path.endswith(".py"):
                    churn[path] = churn.get(path, 0) + 1
    except Exception:
        pass
    return churn


class ChurnAnalyzer:
    def __init__(self, churn_data: dict[str, int] | None = None):
        self._churn_data = churn_data or {}

    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]:
        # Churn analyzer doesn't produce standalone findings;
        # it provides data that the scorer uses to boost priority
        # of findings from other analyzers.
        return []
```

**Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_analyzers/test_churn.py -v
```

Expected: all 2 tests PASS

**Step 5: Commit**

```bash
git add src/tech_debtor/analyzers/churn.py tests/test_analyzers/test_churn.py
git commit -m "feat: add churn analyzer (git history file change frequency)"
```

---

### Task 11: Scoring with Churn Boost

**Files:**
- Create: `src/tech_debtor/scoring.py`
- Create: `tests/test_scoring.py`

**Step 1: Write the failing test**

Create `tests/test_scoring.py`:

```python
from tech_debtor.scoring import prioritize_findings
from tech_debtor.models import Finding, DebtType, Severity


def _make_finding(file_path: str, severity: Severity, minutes: int) -> Finding:
    return Finding(
        file_path=file_path,
        line=1,
        end_line=10,
        debt_type=DebtType.COMPLEXITY,
        severity=severity,
        message="test",
        suggestion="test",
        remediation_minutes=minutes,
    )


def test_prioritize_by_severity():
    findings = [
        _make_finding("a.py", Severity.LOW, 10),
        _make_finding("b.py", Severity.CRITICAL, 10),
        _make_finding("c.py", Severity.MEDIUM, 10),
    ]
    result = prioritize_findings(findings, churn={})
    assert result[0].severity == Severity.CRITICAL
    assert result[-1].severity == Severity.LOW


def test_churn_boosts_priority():
    f_low_churn = _make_finding("stable.py", Severity.MEDIUM, 10)
    f_high_churn = _make_finding("hotspot.py", Severity.MEDIUM, 10)
    findings = [f_low_churn, f_high_churn]
    churn = {"hotspot.py": 50, "stable.py": 1}
    result = prioritize_findings(findings, churn=churn)
    assert result[0].file_path == "hotspot.py"


def test_quick_wins_within_same_severity():
    f_slow = _make_finding("a.py", Severity.MEDIUM, 60)
    f_quick = _make_finding("b.py", Severity.MEDIUM, 5)
    findings = [f_slow, f_quick]
    result = prioritize_findings(findings, churn={})
    # Quick wins first within same severity
    assert result[0].file_path == "b.py"
```

**Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_scoring.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

Create `src/tech_debtor/scoring.py`:

```python
from __future__ import annotations

from tech_debtor.models import Finding


def _priority_key(finding: Finding, churn: dict[str, int]) -> tuple[float, ...]:
    """Higher priority = more negative key (sorts first).

    Composite: severity (desc), churn (desc), remediation (asc = quick wins first).
    """
    churn_count = churn.get(finding.file_path, 0)
    return (
        -finding.severity,        # higher severity first
        -churn_count,             # higher churn first
        finding.remediation_minutes,  # quick wins first
    )


def prioritize_findings(
    findings: list[Finding],
    churn: dict[str, int],
) -> list[Finding]:
    return sorted(findings, key=lambda f: _priority_key(f, churn))
```

**Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_scoring.py -v
```

Expected: all 3 tests PASS

**Step 5: Commit**

```bash
git add src/tech_debtor/scoring.py tests/test_scoring.py
git commit -m "feat: add scoring with churn-boosted prioritization"
```

---

### Task 12: Terminal Reporter

**Files:**
- Create: `src/tech_debtor/reporters/__init__.py`
- Create: `src/tech_debtor/reporters/terminal.py`
- Create: `tests/test_reporters.py`

**Step 1: Write the failing test**

Create `tests/test_reporters.py`:

```python
from io import StringIO

from tech_debtor.reporters.terminal import render_terminal
from tech_debtor.models import Finding, FileReport, ProjectReport, DebtType, Severity


def _make_report() -> ProjectReport:
    finding = Finding(
        file_path="src/foo.py",
        line=10,
        end_line=20,
        debt_type=DebtType.COMPLEXITY,
        severity=Severity.HIGH,
        message="Cyclomatic complexity: 18 (threshold: 10)",
        suggestion="Break into smaller functions",
        remediation_minutes=45,
        symbol="process",
    )
    file_report = FileReport(file_path="src/foo.py", lines_of_code=200, findings=[finding])
    return ProjectReport(file_reports=[file_report])


def test_render_terminal_produces_output(capsys):
    report = _make_report()
    render_terminal(report, churn={})
    captured = capsys.readouterr()
    assert "COMPLEXITY" in captured.out
    assert "process" in captured.out
    assert "Debt Score" in captured.out


def test_render_terminal_empty_report(capsys):
    report = ProjectReport(file_reports=[])
    render_terminal(report, churn={})
    captured = capsys.readouterr()
    assert "No findings" in captured.out or "Excellent" in captured.out or "0" in captured.out
```

**Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_reporters.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

Create `src/tech_debtor/reporters/__init__.py` (empty) and `src/tech_debtor/reporters/terminal.py`:

```python
from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from tech_debtor.models import ProjectReport, Finding, Severity, DebtType
from tech_debtor.scoring import prioritize_findings

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}

DEBT_TYPE_LABELS = {
    DebtType.COMPLEXITY: "COMPLEXITY",
    DebtType.SMELL: "SMELL",
    DebtType.DUPLICATION: "DUPLICATION",
    DebtType.DEAD_CODE: "DEAD CODE",
    DebtType.CHURN: "CHURN",
}

RATING_COLORS = {
    "Excellent": "bold green",
    "Good": "green",
    "Fair": "yellow",
    "Poor": "red",
    "Critical": "bold red",
}


def render_terminal(
    report: ProjectReport,
    churn: dict[str, int],
    console: Console | None = None,
) -> None:
    console = console or Console()
    findings = prioritize_findings(report.all_findings, churn)

    # Header
    console.print(f"\n[bold]tech-debtor[/bold] — scanned {report.total_files} files\n")

    if not findings:
        console.print("[green]No findings — code looks clean![/green]\n")

    # Findings
    for f in findings:
        color = SEVERITY_COLORS.get(f.severity, "white")
        label = DEBT_TYPE_LABELS.get(f.debt_type, f.debt_type.value.upper())
        location = f"{f.file_path}:{f.line}"
        if f.symbol:
            location += f":{f.symbol}"

        console.print(f" [{color}]{label}[/{color}]  {location}")
        console.print(f"   {f.message}")
        console.print(f"   [dim]→ {f.suggestion}[/dim]")
        console.print(f"   [dim]Remediation: ~{f.remediation_minutes} min | Severity: {f.severity.name.lower()}[/dim]\n")

    # Summary
    score = report.debt_score
    rating = report.debt_rating
    rating_color = RATING_COLORS.get(rating, "white")
    total_minutes = report.total_remediation_minutes
    hours = total_minutes / 60

    severity_counts = {s: 0 for s in Severity}
    for f in findings:
        severity_counts[f.severity] += 1
    counts_str = ", ".join(
        f"{count} {sev.name.lower()}" for sev, count in sorted(severity_counts.items(), reverse=True) if count > 0
    )

    console.rule()
    console.print(f" Debt Score: [{rating_color}]{score}/100 ({rating})[/{rating_color}]")
    console.print(f" Total items: {len(findings)} ({counts_str})")
    console.print(f" Est. remediation: ~{hours:.0f} hours" if hours >= 1 else f" Est. remediation: ~{total_minutes} min")

    # Hotspots (top 3 churned files with findings)
    if churn:
        file_churn = {}
        for f in findings:
            c = churn.get(f.file_path, 0)
            if c > 0:
                file_churn[f.file_path] = max(file_churn.get(f.file_path, 0), c)
        if file_churn:
            hotspots = sorted(file_churn, key=file_churn.get, reverse=True)[:3]  # type: ignore[arg-type]
            console.print(f" Hotspots: {', '.join(hotspots)}")
    console.rule()
    console.print()
```

**Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_reporters.py -v
```

Expected: all 2 tests PASS

**Step 5: Commit**

```bash
git add src/tech_debtor/reporters/ tests/test_reporters.py
git commit -m "feat: add rich terminal reporter with summary and hotspots"
```

---

### Task 13: JSON Reporter

**Files:**
- Create: `src/tech_debtor/reporters/json_reporter.py`
- Create: `tests/test_json_reporter.py`

**Step 1: Write the failing test**

Create `tests/test_json_reporter.py`:

```python
import json

from tech_debtor.reporters.json_reporter import render_json
from tech_debtor.models import Finding, FileReport, ProjectReport, DebtType, Severity


def test_render_json():
    finding = Finding(
        file_path="src/foo.py",
        line=10,
        end_line=20,
        debt_type=DebtType.COMPLEXITY,
        severity=Severity.HIGH,
        message="Cyclomatic complexity: 18",
        suggestion="Simplify",
        remediation_minutes=45,
        symbol="process",
    )
    file_report = FileReport(file_path="src/foo.py", lines_of_code=200, findings=[finding])
    report = ProjectReport(file_reports=[file_report])

    output = render_json(report, churn={})
    data = json.loads(output)

    assert data["debt_score"] == 45
    assert data["debt_rating"] == "Fair"
    assert data["total_files"] == 1
    assert data["total_findings"] == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["file_path"] == "src/foo.py"
    assert data["findings"][0]["severity"] == "high"
```

**Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_json_reporter.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

Create `src/tech_debtor/reporters/json_reporter.py`:

```python
from __future__ import annotations

import json

from tech_debtor.models import ProjectReport
from tech_debtor.scoring import prioritize_findings


def render_json(report: ProjectReport, churn: dict[str, int]) -> str:
    findings = prioritize_findings(report.all_findings, churn)

    data = {
        "debt_score": report.debt_score,
        "debt_rating": report.debt_rating,
        "total_files": report.total_files,
        "total_findings": report.total_findings,
        "total_remediation_minutes": report.total_remediation_minutes,
        "findings": [
            {
                "file_path": f.file_path,
                "line": f.line,
                "end_line": f.end_line,
                "debt_type": f.debt_type.value,
                "severity": f.severity.name.lower(),
                "message": f.message,
                "suggestion": f.suggestion,
                "remediation_minutes": f.remediation_minutes,
                "symbol": f.symbol,
            }
            for f in findings
        ],
    }
    return json.dumps(data, indent=2)
```

**Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_json_reporter.py -v
```

Expected: all 1 test PASS

**Step 5: Commit**

```bash
git add src/tech_debtor/reporters/json_reporter.py tests/test_json_reporter.py
git commit -m "feat: add JSON reporter"
```

---

### Task 14: CLI Entry Point

**Files:**
- Create: `src/tech_debtor/cli.py`
- Create: `tests/test_cli.py`

**Step 1: Write the failing test**

Create `tests/test_cli.py`:

```python
from pathlib import Path
from click.testing import CliRunner

from tech_debtor.cli import main


def _make_project(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "simple.py").write_text("def add(x, y):\n    return x + y\n")
    (src / "complex.py").write_text(
        "def f(data):\n"
        + "    if data:\n" * 20
        + "        pass\n"
    )


def test_analyze_command(tmp_path):
    _make_project(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(tmp_path / "src")])
    assert result.exit_code == 0
    assert "Debt Score" in result.output


def test_analyze_json(tmp_path):
    _make_project(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(tmp_path / "src"), "--json"])
    assert result.exit_code == 0
    assert '"debt_score"' in result.output


def test_score_command(tmp_path):
    _make_project(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["score", str(tmp_path / "src")])
    assert result.exit_code == 0


def test_score_fail_above(tmp_path):
    _make_project(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["score", str(tmp_path / "src"), "--fail-above", "0"])
    # Should fail because any findings push score above 0
    assert result.exit_code == 1
```

**Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

Create `src/tech_debtor/cli.py`:

```python
from __future__ import annotations

import sys
from pathlib import Path

import click

from tech_debtor import __version__
from tech_debtor.analyzers.base import parse_python
from tech_debtor.analyzers.churn import ChurnAnalyzer, get_file_churn
from tech_debtor.analyzers.complexity import ComplexityAnalyzer
from tech_debtor.analyzers.deadcode import DeadCodeAnalyzer
from tech_debtor.analyzers.duplication import DuplicationAnalyzer
from tech_debtor.analyzers.smells import SmellAnalyzer
from tech_debtor.config import Config, load_config
from tech_debtor.models import FileReport, ProjectReport
from tech_debtor.reporters.json_reporter import render_json
from tech_debtor.reporters.terminal import render_terminal
from tech_debtor.scanner import scan_python_files

ALL_ANALYZERS = {
    "complexity": ComplexityAnalyzer,
    "smells": SmellAnalyzer,
    "duplication": DuplicationAnalyzer,
    "deadcode": DeadCodeAnalyzer,
}


def _run_analysis(
    path: Path,
    config: Config,
    checks: list[str] | None = None,
) -> tuple[ProjectReport, dict[str, int]]:
    analyzers = []
    selected = checks or list(ALL_ANALYZERS.keys())
    for name in selected:
        cls = ALL_ANALYZERS.get(name)
        if cls:
            analyzers.append(cls())

    churn = get_file_churn(path)
    file_reports = []

    for file_path in scan_python_files(path, exclude=config.exclude):
        source = file_path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = parse_python(source)
        except Exception:
            continue

        findings = []
        for analyzer in analyzers:
            findings.extend(analyzer.analyze(str(file_path), source, tree, config))

        loc = source.count("\n")
        file_reports.append(FileReport(
            file_path=str(file_path),
            lines_of_code=loc,
            findings=findings,
        ))

    report = ProjectReport(file_reports=file_reports, cost_per_line=config.cost_per_line)
    return report, churn


@click.group()
@click.version_option(version=__version__)
def main():
    """tech-debtor: Python technical debt analyzer."""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--check", default=None, help="Comma-separated checks: complexity,smells,duplication,deadcode")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--min-severity", default=None, type=click.Choice(["low", "medium", "high", "critical"]))
@click.option("--verbose", is_flag=True, help="Show detailed output")
def analyze(path: str, check: str | None, as_json: bool, min_severity: str | None, verbose: bool):
    """Analyze Python files for technical debt."""
    target = Path(path)
    config = load_config(target if target.is_dir() else target.parent)

    checks = check.split(",") if check else None
    report, churn = _run_analysis(target, config, checks)

    if min_severity:
        from tech_debtor.models import Severity
        threshold = Severity[min_severity.upper()]
        for fr in report.file_reports:
            fr.findings = [f for f in fr.findings if f.severity >= threshold]

    if as_json:
        click.echo(render_json(report, churn))
    else:
        render_terminal(report, churn)


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--fail-above", type=int, default=None, help="Exit with code 1 if debt score exceeds this value")
def score(path: str, fail_above: int | None):
    """Show debt score summary."""
    target = Path(path)
    config = load_config(target if target.is_dir() else target.parent)
    report, churn = _run_analysis(target, config)

    render_terminal(report, churn)

    if fail_above is not None and report.debt_score > fail_above:
        raise SystemExit(1)
```

**Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_cli.py -v
```

Expected: all 4 tests PASS

**Step 5: Commit**

```bash
git add src/tech_debtor/cli.py tests/test_cli.py
git commit -m "feat: add CLI with analyze and score commands"
```

---

### Task 15: Integration Test and Final Polish

**Files:**
- Create: `tests/fixtures/` (sample files)
- Create: `tests/test_integration.py`

**Step 1: Write the integration test**

Create `tests/fixtures/messy_code.py`:

```python
import os
import json
import sys

def process_data(data, config, logger, db, cache, validator, formatter, output):
    result = []
    for item in data:
        if item.get("active"):
            if item.get("type") == "A":
                if item.get("value") > 100:
                    if validator.check(item):
                        result.append(formatter.format(item))
                    else:
                        result.append(item)
                else:
                    result.append(item)
            elif item.get("type") == "B":
                result.append(item)
            else:
                for sub in item.get("children", []):
                    if sub.get("valid"):
                        result.append(sub)
    return result


def transform_data(data, config, logger, db, cache, validator, formatter, output):
    result = []
    for item in data:
        if item.get("active"):
            if item.get("type") == "A":
                if item.get("value") > 100:
                    if validator.check(item):
                        result.append(formatter.format(item))
                    else:
                        result.append(item)
                else:
                    result.append(item)
            elif item.get("type") == "B":
                result.append(item)
            else:
                for sub in item.get("children", []):
                    if sub.get("valid"):
                        result.append(sub)
    return result


def unused_helper():
    return "never called"


class GodObject:
    def m1(self): pass
    def m2(self): pass
    def m3(self): pass
    def m4(self): pass
    def m5(self): pass
    def m6(self): pass
    def m7(self): pass
    def m8(self): pass
    def m9(self): pass
    def m10(self): pass
    def m11(self): pass
    def m12(self): pass
    def m13(self): pass
    def m14(self): pass
    def m15(self): pass
    def m16(self): pass
    def m17(self): pass
    def m18(self): pass
    def m19(self): pass
    def m20(self): pass
    def m21(self): pass
```

Create `tests/test_integration.py`:

```python
from pathlib import Path
from click.testing import CliRunner

from tech_debtor.cli import main


FIXTURES = Path(__file__).parent / "fixtures"


def test_full_analysis_on_fixture():
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(FIXTURES)])
    assert result.exit_code == 0
    # Should find all types of debt
    assert "COMPLEXITY" in result.output
    assert "SMELL" in result.output
    assert "DEAD CODE" in result.output
    assert "DUPLICATION" in result.output
    assert "Debt Score" in result.output


def test_json_output_on_fixture():
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(FIXTURES), "--json"])
    assert result.exit_code == 0
    import json
    data = json.loads(result.output)
    assert data["total_findings"] > 0
    debt_types = {f["debt_type"] for f in data["findings"]}
    assert "complexity" in debt_types
    assert "smell" in debt_types


def test_score_fail_above_on_fixture():
    runner = CliRunner()
    result = runner.invoke(main, ["score", str(FIXTURES), "--fail-above", "0"])
    assert result.exit_code == 1
```

**Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_integration.py -v
```

Expected: FAIL (fixture file doesn't exist yet or tests not wired)

**Step 3: Create the fixture file and run**

The fixture file is created above. Run:

```bash
uv run pytest tests/test_integration.py -v
```

Expected: all 3 tests PASS

**Step 4: Run full test suite**

```bash
uv run pytest -v
```

Expected: ALL tests PASS

**Step 5: Run ruff**

```bash
uv run ruff check src/ tests/
```

Fix any issues found.

**Step 6: Commit**

```bash
git add tests/fixtures/ tests/test_integration.py
git commit -m "feat: add integration tests with messy code fixture"
```

---

### Task 16: Final Verification

**Step 1: Run the tool on itself**

```bash
uv run tech-debtor analyze src/
```

Verify it produces output without errors.

**Step 2: Run with JSON**

```bash
uv run tech-debtor analyze src/ --json
```

Verify valid JSON output.

**Step 3: Run score with CI gate**

```bash
uv run tech-debtor score src/
```

**Step 4: Run full test suite one more time**

```bash
uv run pytest -v
uv run ruff check src/ tests/
```

**Step 5: Final commit if any polish was needed**

```bash
git add -A
git commit -m "chore: final polish and self-analysis verification"
```
