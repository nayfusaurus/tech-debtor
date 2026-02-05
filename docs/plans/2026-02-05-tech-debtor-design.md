# tech-debtor: Python Technical Debt Analyzer

## Problem

Teams waste 23-42% of development time on technical debt. Existing tools are either enterprise platforms (SonarQube, CAST) or individual linters (ruff, pylint, radon). Nothing in the Python ecosystem provides a unified, lightweight, CLI-first view that combines code complexity, code smells, duplication, and dead code into a single actionable report with prioritized remediation suggestions.

## Solution

A CLI tool that analyzes Python projects for code-level technical debt and produces prioritized, actionable reports with remediation estimates.

## Target User

Individual developers who want fast feedback on the health of their Python codebase. CLI-first, runs locally, no server required.

## V1 Scope: Code Quality & Complexity

### Analysis Dimensions

1. **Complexity** — Cyclomatic and cognitive complexity per function/method. Flags functions that are hard to understand, test, and modify.

2. **Code smells** — Long functions, deep nesting, too many parameters, god classes (classes with too many methods/lines).

3. **Duplication** — Structural duplicate detection using AST comparison (not text matching).

4. **Dead code** — Unused imports, unreachable branches, uncalled functions/classes.

5. **Churn correlation** — If git history is available, cross-reference complexity with change frequency. High-complexity + high-churn = highest priority debt.

Each finding includes severity (critical/high/medium/low), estimated remediation effort in minutes (SQALE-style), and a concrete suggestion.

## CLI Interface

```bash
# Analyze a path (directory or file)
tech-debtor analyze src/

# Analyze with specific checks only
tech-debtor analyze src/ --check complexity,smells

# JSON output for CI/scripting
tech-debtor analyze src/ --json

# Show only critical/high severity
tech-debtor analyze src/ --min-severity high

# Summary score with CI gate
tech-debtor score src/
tech-debtor score src/ --fail-above 60  # exit code 1 if score > 60

# Detailed single-file analysis
tech-debtor analyze src/models/user.py --verbose
```

### Terminal Output

```
tech-debtor v0.1.0 — scanning src/ (47 files)

 COMPLEXITY  src/services/payment.py:process_payment
   Cognitive complexity: 34 (threshold: 15)
   Cyclomatic complexity: 18 (threshold: 10)
   → Break into smaller functions, extract validation logic
   Remediation: ~45 min | Severity: critical

 SMELL  src/models/user.py:UserManager
   God class: 22 methods, 580 lines
   → Split into focused classes (UserAuth, UserProfile, UserQuery)
   Remediation: ~120 min | Severity: high

 DEAD CODE  src/utils/helpers.py:format_legacy_date
   Function never called (0 references found)
   → Remove or verify if used dynamically
   Remediation: ~5 min | Severity: low

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Debt Score: 62/100 (Fair)
 Total items: 23 (4 critical, 7 high, 8 medium, 4 low)
 Est. remediation: ~18 hours
 Hotspots: payment.py (high complexity + high churn)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Scoring

### Debt Score (0-100)

- **0-20**: Excellent — minimal debt
- **21-40**: Good — some debt, manageable
- **41-60**: Fair — noticeable debt, plan remediation
- **61-80**: Poor — significant debt impacting velocity
- **81-100**: Critical — urgent attention needed

### Formula

`debt_score = min(100, (total_remediation_minutes / (lines_of_code * cost_per_line)) * 100)`

Default cost-per-line: 0.5 minutes (configurable).

### Prioritization

Items ranked by composite of:
1. Severity (weighted by type)
2. Churn (frequently changed files get priority boost)
3. Remediation effort (quick wins surfaced first within same severity)

## Architecture

### Components

- **Scanner** — Directory walker, discovers Python files, respects .gitignore and config exclusions.
- **Analyzers** (pluggable, each handles one debt type):
  - `ComplexityAnalyzer` — Cyclomatic + cognitive complexity
  - `SmellAnalyzer` — Long functions, deep nesting, too-many-params, god classes
  - `DuplicationAnalyzer` — AST-based structural duplicate detection
  - `DeadCodeAnalyzer` — Unused imports, unreachable code, uncalled functions
  - `ChurnAnalyzer` — Git log integration, change frequency per file
- **Scorer** — Aggregates findings into per-file and project-wide debt score.
- **Reporter** — Terminal (rich) and JSON output.
- **Config** — Reads `[tool.tech-debtor]` from `pyproject.toml`.

### Parser

Uses `tree-sitter` with `tree-sitter-python` for AST parsing. Provides graceful error recovery for files with syntax errors and richer node types than the stdlib `ast` module.

## Configuration

```toml
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

## Project Structure

```
tech-debtor/
├── pyproject.toml
├── src/
│   └── tech_debtor/
│       ├── __init__.py
│       ├── cli.py              # Click CLI entry point
│       ├── scanner.py          # File discovery, .gitignore handling
│       ├── analyzers/
│       │   ├── __init__.py
│       │   ├── base.py         # BaseAnalyzer protocol
│       │   ├── complexity.py   # Cyclomatic + cognitive complexity
│       │   ├── smells.py       # Code smells detection
│       │   ├── duplication.py  # AST-based duplicate detection
│       │   ├── deadcode.py     # Unused code detection
│       │   └── churn.py        # Git history analysis
│       ├── scoring.py          # Debt score calculation
│       ├── models.py           # Finding, FileReport, ProjectReport dataclasses
│       ├── config.py           # pyproject.toml config loading
│       └── reporters/
│           ├── __init__.py
│           ├── terminal.py     # Rich terminal output
│           └── json.py         # JSON output
└── tests/
    ├── conftest.py
    ├── test_analyzers/
    ├── test_scoring.py
    ├── test_cli.py
    └── fixtures/               # Sample Python files with known debt
```

## Dependencies

- `tree-sitter` + `tree-sitter-python` — AST parsing
- `rich` — Terminal output
- `click` — CLI framework
- `gitpython` — Git history analysis
- `tomli` (stdlib `tomllib` on 3.11+) — Config loading

Dev dependencies: `pytest`, `ruff`, `mypy`

## Future (Post-V1)

- Dependency health (outdated packages, vulnerabilities)
- Test & documentation gap analysis
- Trend tracking (compare scores over time)
- Team dashboard / HTML report output
- Pre-commit hook integration
- VS Code extension
