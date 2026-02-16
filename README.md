# tech-debtor

A CLI tool that analyzes Python projects for code-level technical debt and produces prioritized, actionable reports with remediation estimates.

## What It Detects

- **Complexity** — Cyclomatic and cognitive complexity per function
- **Code smells** — Long functions, deep nesting, too many parameters, god classes
- **Duplication** — Structural duplicate detection using AST comparison
- **Dead code** — Unused imports, uncalled functions
- **Churn correlation** — Cross-references findings with git change frequency to surface hotspots

Each finding includes severity (critical/high/medium/low), estimated remediation effort in minutes, and a concrete suggestion.

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

## Usage

```bash
# Analyze a directory
tech-debtor analyze src/

# Analyze with specific checks only
tech-debtor analyze src/ --check complexity,smells

# JSON output for CI/scripting
tech-debtor analyze src/ --json

# Filter by severity
tech-debtor analyze src/ --min-severity high

# Debt score with CI gate (exit code 1 if score exceeds threshold)
tech-debtor score src/ --fail-above 60
```

## Example Output

```text
tech-debtor — scanned 47 files

 COMPLEXITY  src/services/payment.py:10:process_payment
   Cognitive complexity: 34 (threshold: 15)
   → Reduce nesting depth, extract helper functions, simplify conditionals
   Remediation: ~80 min | Severity: critical

 SMELL  src/models/user.py:5:UserManager
   God class: 22 methods (threshold: 20)
   → Split into focused classes using single-responsibility principle
   Remediation: ~110 min | Severity: high

 DEAD CODE  src/utils/helpers.py:1:format_legacy_date
   Unused function: format_legacy_date (0 references in file)
   → Remove or verify if used dynamically or by external callers
   Remediation: ~5 min | Severity: low

────────────────────────────────────────────────────────────────────────────────
 Debt Score: 62/100 (Poor)
 Total items: 23 (4 critical, 7 high, 8 medium, 4 low)
 Est. remediation: ~18 hours
 Hotspots: payment.py, user.py, api_client.py
────────────────────────────────────────────────────────────────────────────────
```

## Debt Score

The debt score (0–100) is calculated as:

```text
debt_score = min(100, (total_remediation_minutes / (lines_of_code * cost_per_line)) * 100)
```

| Score  | Rating    | Meaning                             |
| ------ | --------- | ----------------------------------- |
| 0–20   | Excellent | Minimal debt                        |
| 21–40  | Good      | Some debt, manageable               |
| 41–60  | Fair      | Noticeable debt, plan remediation   |
| 61–80  | Poor      | Significant debt impacting velocity |
| 81–100 | Critical  | Urgent attention needed             |

Findings are prioritized by: severity (highest first), churn frequency (hotspots first), then remediation effort (quick wins first within same severity).

## Configuration

Add to your `pyproject.toml`:

```toml
[tool.tech-debtor]
max-complexity = 15          # Cyclomatic complexity threshold
max-cognitive-complexity = 10 # Cognitive complexity threshold
max-function-length = 50     # Max lines per function
max-parameters = 5           # Max parameters per function
max-nesting-depth = 4        # Max nesting depth
min-severity = "medium"      # Minimum severity to report
exclude = ["tests/", "migrations/"]
cost-per-line = 0.5          # Minutes per line (for debt score calculation)
```

## Development

```bash
git clone https://github.com/nayfusaurus/tech-debtor.git
cd tech-debtor
uv sync

# Run tests
uv run pytest -v

# Run linter
uv run ruff check src/ tests/

# Run the tool on itself
uv run tech-debtor analyze src/
```

## License

APACHE 2.0
