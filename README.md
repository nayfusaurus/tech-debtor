# tech-debtor

[![Tests](https://github.com/nayfusaurus/tech-debtor/actions/workflows/test.yml/badge.svg)](https://github.com/nayfusaurus/tech-debtor/actions/workflows/test.yml)
[![Lint](https://github.com/nayfusaurus/tech-debtor/actions/workflows/lint.yml/badge.svg)](https://github.com/nayfusaurus/tech-debtor/actions/workflows/lint.yml)
[![Security](https://github.com/nayfusaurus/tech-debtor/actions/workflows/security.yml/badge.svg)](https://github.com/nayfusaurus/tech-debtor/actions/workflows/security.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

A CLI tool that analyzes Python projects for technical debt and produces prioritized, actionable reports with remediation estimates.

## Features

- **Complexity analysis** — Cyclomatic and cognitive complexity per function
- **Code smells** — Long functions, deep nesting, too many parameters, god classes
- **Duplication detection** — Structural duplicate detection via AST fingerprinting
- **Dead code** — Unused imports and uncalled functions
- **Exception anti-patterns** — Bare excepts, swallowed exceptions, resource leaks, divide-by-zero risks (CWE-703, CWE-772, CWE-369, CWE-595, CWE-1077)
- **Security patterns** — Hard-coded credentials, unsafe deserialization, command/SQL injection, eval/exec, deprecated stdlib imports (CWE-798, CWE-502, CWE-78, CWE-89, CWE-95, CWE-477)
- **SQALE metrics** — Industry-standard Technical Debt Ratio and A–E rating
- **Churn correlation** — Cross-references findings with git change frequency to surface hotspots
- **CI integration** — `--fail-above` and `--fail-rating` gates for automated quality enforcement

Each finding includes severity, estimated remediation effort in minutes, and a concrete suggestion.

## Installation

Requires Python 3.12+.

```bash
# Using uv (recommended)
uv tool install tech-debtor

# Or install from source
git clone https://github.com/nayfusaurus/tech-debtor.git
cd tech-debtor
uv sync
```

## Quick Start

```bash
# Analyze a project
tech-debtor analyze src/

# Run specific checks only
tech-debtor analyze src/ --check complexity,security

# JSON output for CI pipelines
tech-debtor analyze src/ --json

# Filter by severity
tech-debtor analyze src/ --min-severity high

# CI gate: fail if debt score exceeds threshold
tech-debtor score src/ --fail-above 60

# CI gate: fail if SQALE rating is worse than C
tech-debtor score src/ --fail-rating C
```

## Example Output

```text
tech-debtor — scanned 47 files

 COMPLEXITY  src/services/payment.py:10:process_payment
   Cognitive complexity: 34 (threshold: 15)
   → Reduce nesting depth, extract helper functions, simplify conditionals
   Remediation: ~80 min | Severity: critical

 SECURITY  src/config/settings.py:12
   CWE-798: Hard-coded credential in variable 'API_SECRET'
   → Use environment variables (os.getenv()) or a secrets manager
   Remediation: ~15 min | Severity: critical

 DEAD CODE  src/utils/helpers.py:1:format_legacy_date
   Unused function: format_legacy_date (0 references in file)
   → Remove or verify if used dynamically or by external callers
   Remediation: ~5 min | Severity: low

────────────────────────────────────────────────────────────────────────────────
 Debt Score: 62/100 (Poor)
 Total items: 23 (4 critical, 7 high, 8 medium, 4 low)
 Est. remediation: ~18 hours
 Hotspots: payment.py, settings.py, api_client.py
────────────────────────────────────────────────────────────────────────────────
╭─────────────────────────── SQALE Metrics ────────────────────────────────────╮
│ SQALE Index: 18.0 hours (1080 min)                                          │
│ Technical Debt Ratio: 22.5%                                                 │
│ SQALE Rating: C (Moderate)                                                  │
╰─────────────────────────────────────────────────────────────────────────────╯
```

## Available Checks

| Check         | Description                                                    |
| ------------- | -------------------------------------------------------------- |
| `complexity`  | Cyclomatic and cognitive complexity per function               |
| `smells`      | Long functions, deep nesting, too many params, god classes     |
| `duplication` | Structural duplicate detection using AST comparison            |
| `deadcode`    | Unused imports and uncalled top-level functions                |
| `exceptions`  | Exception handling anti-patterns (7 CWE patterns)              |
| `security`    | Security anti-patterns and deprecated imports (6 CWE patterns) |

Run individual checks with `--check`:

```bash
tech-debtor analyze src/ --check security,exceptions
```

## SQALE Rating

The SQALE rating is based on the Technical Debt Ratio (TDR), which measures remediation cost relative to development cost:

```text
TDR = (total_remediation_minutes / (lines_of_code × cost_per_line)) × 100
```

| TDR    | Rating | Meaning                             |
| ------ | ------ | ----------------------------------- |
| 0–5%   | A      | Excellent — minimal debt            |
| 5–10%  | B      | Good — manageable debt              |
| 10–20% | C      | Moderate — plan remediation         |
| 20–50% | D      | Poor — significant debt             |
| >50%   | E      | Critical — urgent attention needed  |

## Configuration

Add to your `pyproject.toml`:

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

# SQALE thresholds (TDR percentages)
sqale-threshold-a = 5.0
sqale-threshold-b = 10.0
sqale-threshold-c = 20.0
sqale-threshold-d = 50.0

# Toggle individual checks
check-hardcoded-credentials = true
check-unsafe-deserialization = true
check-command-injection = true
check-sql-injection = true
check-deprecated-imports = true
```

## Development

```bash
git clone https://github.com/nayfusaurus/tech-debtor.git
cd tech-debtor
uv sync

uv run pytest -v              # Run tests
uv run ruff check src/ tests/ # Lint
uv run mypy src/              # Type check
uv run tech-debtor analyze src/ # Self-analysis
```

## License

[Apache 2.0](LICENSE)
