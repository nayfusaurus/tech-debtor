# CLAUDE.md

## Project Overview

tech-debtor is a CLI tool that analyzes Python projects for code-level technical debt and produces prioritized, actionable reports with remediation estimates.

## Tech Stack

- **Python 3.12+** with **uv** for package management
- **tree-sitter** + **tree-sitter-python** for AST parsing
- **rich** for terminal output
- **click** for CLI framework
- **gitpython** for git history analysis
- **pytest** for testing, **ruff** for linting, **mypy** for type checking

## Commands

```bash
# Run tests
uv run pytest -v

# Run linter
uv run ruff check src/ tests/

# Run type checker
uv run mypy src/

# Run the tool
uv run tech-debtor analyze src/
uv run tech-debtor analyze src/ --json
uv run tech-debtor score src/ --fail-above 60
```

## Architecture

```
src/tech_debtor/
├── cli.py              # Click CLI entry point (analyze, score commands)
├── scanner.py          # File discovery, .gitignore/exclusion handling
├── config.py           # Reads [tool.tech-debtor] from pyproject.toml
├── models.py           # Finding, FileReport, ProjectReport dataclasses
├── scoring.py          # Churn-boosted prioritization of findings
├── analyzers/
│   ├── base.py         # tree-sitter parser helpers + Analyzer protocol
│   ├── complexity.py   # Cyclomatic + cognitive complexity per function
│   ├── smells.py       # Long functions, deep nesting, too-many-params, god classes
│   ├── duplication.py  # AST structural fingerprint comparison
│   ├── deadcode.py     # Unused imports + uncalled top-level functions
│   └── churn.py        # Git commit frequency per file
└── reporters/
    ├── terminal.py     # Rich terminal output
    └── json_reporter.py # JSON output
```

**Pipeline:** scanner discovers .py files → tree-sitter parses each into AST → pluggable analyzers walk ASTs producing Findings → scorer prioritizes by severity/churn/effort → reporter renders output.

## Code Conventions

- All source uses `from __future__ import annotations`
- Analyzers implement the `Analyzer` protocol from `analyzers/base.py`
- Severity is an IntEnum (LOW=1..CRITICAL=4), DebtType is a StrEnum
- Finding is a frozen dataclass; FileReport/ProjectReport are mutable
- Dead code analyzer only checks within a single file (cross-file analysis is out of scope for v1)
- Config keys in pyproject.toml use kebab-case, mapped to snake_case in Python

## Testing

- Tests live in `tests/` mirroring the source structure
- `tests/fixtures/messy_code.py` is an intentionally messy file for integration tests
- Ruff ignores `F401`/`F811` in `tests/fixtures/*` (unused imports are intentional test data)
- 41 tests total, all should pass
