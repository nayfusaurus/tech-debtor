# GitHub Workflows Implementation Plan

Implementation order optimized for: foundational infrastructure → security → automation → community → advanced features

---

## 1. Test Suite Runner ⭐ CRITICAL

**Purpose:** Run tests on every push/PR to catch regressions

**Files to create:**
- `.github/workflows/test.yml`

**What it does:**
```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix:
        python-version: ['3.12', '3.13']
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv sync
      - run: uv run pytest -v --cov=tech_debtor --cov-report=xml
      - uses: codecov/codecov-action@v5  # Upload coverage
```

**Benefits:**
- Catch bugs before merge
- Cross-platform validation (Windows, macOS, Linux)
- Multi-version support (Python 3.12, 3.13)
- Coverage tracking

**Configuration needed:**
- Sign up for Codecov (free for public repos): https://about.codecov.io/
- Add `CODECOV_TOKEN` to GitHub secrets (if private repo)
- Badge in README: `[![Coverage](https://codecov.io/gh/USER/tech-debtor/badge.svg)](https://codecov.io/gh/USER/tech-debtor)`

**Estimated time:** 30 minutes

---

## 2. Lint & Type Check ⭐ CRITICAL

**Purpose:** Enforce code quality and catch type errors

**Files to create:**
- `.github/workflows/lint.yml`

**What it does:**
```yaml
name: Lint
on: [push, pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv sync
      - run: uv run ruff check src/ tests/
      - run: uv run ruff format --check src/ tests/
      - run: uv run mypy src/
```

**Benefits:**
- Consistent code style
- Catch type errors early
- Auto-review code quality
- Block PRs with issues

**Configuration needed:**
- Add `[tool.mypy]` to `pyproject.toml`:
```toml
[tool.mypy]
python_version = "3.12"
strict = false  # Start with false, enable later
warn_unused_ignores = true
warn_redundant_casts = true
disallow_untyped_defs = false  # Enable gradually
```

**Estimated time:** 20 minutes

---

## 3. Dependency Version Check & Upgrade ⭐ HIGH

**Purpose:** Ensure dependencies are up-to-date and compatible

**Current dependencies:**
```toml
tree-sitter>=0.23          # Current: 0.23.x
tree-sitter-python>=0.23   # Current: 0.23.x
rich>=13.0                 # Current: 14.3.2 ✅
click>=8.0                 # Current: 8.3.1 ✅
gitpython>=3.1             # Current: 3.1.46 ✅
```

**Status:** All dependencies are using latest compatible versions! ✅

**Upgrade process:**
```bash
# Check for outdated packages
uv pip list --outdated

# Upgrade specific package
uv add "package@latest"

# Test after upgrade
uv run pytest -v

# Update lock file
uv lock --upgrade
```

**Recommended changes to pyproject.toml:**
```toml
# Option 1: Pin to latest stable (more restrictive)
dependencies = [
    "tree-sitter>=0.23,<0.24",
    "tree-sitter-python>=0.23,<0.24",
    "rich>=14.0,<15.0",
    "click>=8.0,<9.0",
    "gitpython>=3.1,<4.0",
]

# Option 2: Keep flexible (current - RECOMMENDED)
# Current approach is good - allows patch/minor updates
```

**Automated checking workflow:**
```yaml
# .github/workflows/dependency-check.yml
name: Dependency Check
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
  workflow_dispatch:  # Manual trigger
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv pip list --outdated
      - run: uv pip check  # Verify compatibility
```

**Estimated time:** 15 minutes (already up-to-date)

---

## 4. Security Scanning ⭐ HIGH

**Purpose:** Detect vulnerabilities, secrets, and security issues

**Files to create:**
- `.github/workflows/security.yml`

**Recommended tools:**

### A. **Bandit** (Python security linter)
```yaml
- run: uv add --dev bandit
- run: uv run bandit -r src/
```
**Detects:** SQL injection, command injection, hardcoded secrets, insecure functions

### B. **pip-audit** (Dependency vulnerability scanner)
```yaml
- run: uvx pip-audit
```
**Detects:** Known CVEs in dependencies (PyPI packages)

### C. **Trivy** (Comprehensive vulnerability scanner)
```yaml
- uses: aquasecurity/trivy-action@master
  with:
    scan-type: 'fs'
    scan-ref: '.'
```
**Detects:** Dependencies, container images, IaC issues

### D. **Semgrep** (Advanced static analysis)
```yaml
- uses: returntocorp/semgrep-action@v1
```
**Detects:** Security patterns, OWASP Top 10, best practices
**Free tier:** Generous for open source

### E. **Snyk** (All-in-one security platform)
```yaml
- uses: snyk/actions/python@master
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
```
**Detects:** Vulnerabilities, license issues, code quality
**Sign up:** https://snyk.io (free for open source)

### F. **GitHub CodeQL** (Built-in, highly recommended)
```yaml
# .github/workflows/codeql.yml
- uses: github/codeql-action/init@v3
  with:
    languages: python
- uses: github/codeql-action/analyze@v3
```
**Detects:** Security vulnerabilities, code quality issues
**Free:** For public repos, automatically enabled

### G. **TruffleHog** (Secret scanner)
```yaml
- uses: trufflesecurity/trufflehog@main
  with:
    path: ./
```
**Detects:** API keys, passwords, tokens committed to repo

**RECOMMENDED STACK:**
1. **CodeQL** (GitHub native, free, comprehensive) ✅ MUST HAVE
2. **pip-audit** (dependency CVEs, fast, free) ✅ MUST HAVE
3. **Bandit** (Python-specific security, fast) ✅ RECOMMENDED
4. **Trivy** (comprehensive, catches more than pip-audit) ⭐ NICE TO HAVE
5. **Semgrep** (advanced patterns, customizable) ⭐ OPTIONAL

**Configuration needed:**
- Enable CodeQL in repo settings (Security → Code scanning)
- Sign up for Snyk (if using): https://app.snyk.io/signup
- Add `SNYK_TOKEN` to GitHub secrets (if using Snyk)

**Estimated time:** 1 hour (setup + configuration)

---

## 5. PyPI Publishing Setup ⭐ CRITICAL (for releases)

**Purpose:** Automated publishing to PyPI when tags are pushed

**Files to create:**
- `.github/workflows/publish.yml`

**🔒 SECURE SETUP GUIDE:**

### Step 1: Create PyPI Account
1. Sign up at https://pypi.org/account/register/
2. Enable 2FA (REQUIRED for publishing)
3. Verify email

### Step 2: Create TestPyPI Account (for testing)
1. Sign up at https://test.pypi.org/account/register/
2. Enable 2FA
3. Verify email

### Step 3: Configure Trusted Publishing (MOST SECURE - No tokens needed!)

**This is the RECOMMENDED approach** - no API tokens stored anywhere!

1. Go to https://pypi.org/manage/account/publishing/
2. Click "Add a new pending publisher"
3. Fill in:
   - **PyPI Project Name:** `tech-debtor`
   - **Owner:** `nayfusaurus` (or your GitHub username)
   - **Repository name:** `tech-debtor`
   - **Workflow name:** `publish.yml`
   - **Environment name:** `release` (optional but recommended)
4. Click "Add"

Repeat for TestPyPI: https://test.pypi.org/manage/account/publishing/

### Step 4: Workflow Configuration

```yaml
name: Publish to PyPI
on:
  push:
    tags:
      - 'v*'  # Trigger on version tags (v0.1.0, v1.0.0, etc.)

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # REQUIRED for trusted publishing
      contents: read
    environment:
      name: release  # Optional: adds manual approval gate
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5

      - name: Build package
        run: uv build

      # Test on TestPyPI first
      - name: Publish to TestPyPI
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          repository-url: https://test.pypi.org/legacy/

      # Then publish to production PyPI
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
```

### Step 5: Optional Environment Protection

1. Go to repo Settings → Environments
2. Create environment named `release`
3. Add protection rules:
   - ✅ Required reviewers (you)
   - ✅ Wait timer (0 minutes, or add delay)
   - ✅ Deployment branches: only tags matching `v*`

This adds a manual approval step before publishing!

### Alternative: API Token Method (Less Secure)

If trusted publishing doesn't work:

1. Create API token at https://pypi.org/manage/account/token/
2. Scope: "Entire account" or specific project
3. Copy token (starts with `pypi-...`)
4. Add to GitHub Secrets:
   - Settings → Secrets → Actions → New secret
   - Name: `PYPI_TOKEN`
   - Value: `pypi-...`

Workflow change:
```yaml
- name: Publish to PyPI
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    password: ${{ secrets.PYPI_TOKEN }}
```

### Step 6: Test Release Process

```bash
# 1. Update version in pyproject.toml
# version = "0.1.1"

# 2. Commit
git add pyproject.toml
git commit -m "chore: bump version to 0.1.1"

# 3. Create and push tag
git tag v0.1.1
git push origin v0.1.1

# 4. Watch workflow run
# GitHub Actions will build and publish automatically

# 5. Verify on TestPyPI
# https://test.pypi.org/project/tech-debtor/

# 6. Test installation
pip install --index-url https://test.pypi.org/simple/ tech-debtor
```

### Security Best Practices:
- ✅ Use trusted publishing (no tokens)
- ✅ Enable 2FA on PyPI
- ✅ Use environment protection for manual approval
- ✅ Test on TestPyPI first
- ✅ Never commit tokens to git
- ✅ Scope tokens to specific projects (if using tokens)
- ✅ Rotate tokens periodically
- ✅ Use GitHub Environments with required reviewers

**Estimated time:** 45 minutes (including testing)

---

## 6. GitHub Releases Automation ⭐ HIGH

**Purpose:** Create GitHub Releases with binaries when tags are pushed

**Files to create:**
- `.github/workflows/release.yml`

**What it does:**
```yaml
name: Create Release
on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write  # Required to create releases
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5

      - name: Build distributions
        run: uv build

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: dist/*
          generate_release_notes: true
          draft: false
          prerelease: false
```

**Features:**
- Auto-generates release notes from PRs
- Attaches wheel and sdist files
- Links to PyPI package
- Changelog from commits

**Customization:**
```yaml
with:
  body: |
    ## What's Changed
    ${{ steps.changelog.outputs.changelog }}

    ## Installation
    ```bash
    pip install tech-debtor==${{ github.ref_name }}
    ```

    **Full Changelog**: https://github.com/${{ github.repository }}/compare/v0.1.0...${{ github.ref_name }}
```

**Estimated time:** 30 minutes

---

## 7. Release Notes Generator ⭐ MEDIUM

**Purpose:** Auto-generate CHANGELOG.md from conventional commits

**Files to create:**
- `.github/workflows/release-notes.yml`
- `.github/release-drafter.yml`

**Tool: Release Drafter**

**Configuration (.github/release-drafter.yml):**
```yaml
name-template: 'v$RESOLVED_VERSION'
tag-template: 'v$RESOLVED_VERSION'
categories:
  - title: '🚀 Features'
    labels:
      - 'feature'
      - 'enhancement'
  - title: '🐛 Bug Fixes'
    labels:
      - 'bug'
      - 'fix'
  - title: '📚 Documentation'
    labels:
      - 'documentation'
  - title: '🔧 Maintenance'
    labels:
      - 'chore'
      - 'dependencies'
change-template: '- $TITLE (#$NUMBER) @$AUTHOR'
version-resolver:
  major:
    labels:
      - 'major'
      - 'breaking'
  minor:
    labels:
      - 'minor'
      - 'feature'
  patch:
    labels:
      - 'patch'
      - 'bug'
      - 'fix'
  default: patch
template: |
  ## What's Changed

  $CHANGES

  ## Contributors

  $CONTRIBUTORS
```

**Workflow:**
```yaml
name: Release Drafter
on:
  push:
    branches: [main, master]
  pull_request:
    types: [opened, reopened, synchronize]

jobs:
  update_release_draft:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: release-drafter/release-drafter@v6
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Alternative: Conventional Changelog**

If you use conventional commits (feat:, fix:, docs:, etc.):

```yaml
- uses: TriPSs/conventional-changelog-action@v5
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    output-file: "CHANGELOG.md"
```

**Estimated time:** 30 minutes

---

## 8. Self-Analysis Report ⭐ MEDIUM (UNIQUE VALUE!)

**Purpose:** Run tech-debtor on itself, track debt over time, comment on PRs

**Files to create:**
- `.github/workflows/self-analysis.yml`
- `scripts/analyze_and_comment.py` (helper script)

**What it does:**

1. **On every push to main:** Track debt score trends
2. **On PRs:** Comment with debt impact
3. **Store historical data** in GitHub Pages or artifacts
4. **Generate badge** for README

**Workflow:**
```yaml
name: Self-Analysis
on:
  push:
    branches: [main, master]
  pull_request:

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for churn analysis

      - uses: astral-sh/setup-uv@v5
      - run: uv sync

      - name: Run self-analysis
        id: analysis
        run: |
          uv run tech-debtor analyze src/ --json > analysis.json
          echo "score=$(jq -r '.debt_score' analysis.json)" >> $GITHUB_OUTPUT
          echo "findings=$(jq -r '.total_findings' analysis.json)" >> $GITHUB_OUTPUT

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: analysis-${{ github.sha }}
          path: analysis.json

      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const score = ${{ steps.analysis.outputs.score }};
            const findings = ${{ steps.analysis.outputs.findings }};
            const body = `## 📊 Tech Debt Analysis

            - **Debt Score:** ${score}/100
            - **Total Findings:** ${findings}

            <details>
            <summary>View Details</summary>

            \`\`\`
            $(cat analysis.json | jq -r '.findings[] | "- [\(.severity)] \(.file_path):\(.line) - \(.message)"' | head -10)
            \`\`\`

            </details>`;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });

      - name: Update README badge
        if: github.ref == 'refs/heads/main'
        run: |
          SCORE=${{ steps.analysis.outputs.score }}
          COLOR=$([ $SCORE -lt 40 ] && echo "green" || [ $SCORE -lt 60 ] && echo "yellow" || echo "red")
          curl -X POST "https://img.shields.io/badge/debt%20score-${SCORE}%2F100-${COLOR}"
```

**Enhanced version with trend tracking:**

Store results in GitHub Pages:
```yaml
- name: Deploy to GitHub Pages
  uses: peaceiris/actions-gh-pages@v4
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    publish_dir: ./reports
    destination_dir: reports/${{ github.run_number }}
```

**Badge for README:**
```markdown
[![Debt Score](https://img.shields.io/endpoint?url=https://USER.github.io/tech-debtor/badge.json)](https://github.com/USER/tech-debtor/actions/workflows/self-analysis.yml)
```

**Estimated time:** 1.5 hours (including trend visualization)

---

## 9. Documentation Generation ⭐ MEDIUM

**Purpose:** Auto-generate and publish docs to GitHub Wiki

**How GitHub Wiki works:**
- Each repo gets a wiki at `https://github.com/USER/REPO/wiki`
- Wiki is a separate git repository
- Clone with: `git clone https://github.com/USER/REPO.wiki.git`
- Wiki pages are markdown files

**Files to create:**
- `.github/workflows/docs.yml`
- `docs/` directory with markdown files

**Workflow:**
```yaml
name: Update Wiki
on:
  push:
    branches: [main, master]
    paths:
      - 'docs/**'
      - 'README.md'
      - 'src/**/*.py'

jobs:
  update-wiki:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Clone wiki
        run: |
          git clone https://github.com/${{ github.repository }}.wiki.git wiki

      - name: Generate API docs
        run: |
          # Generate from docstrings
          uv run python scripts/generate_api_docs.py > wiki/API-Reference.md

      - name: Copy documentation
        run: |
          cp docs/architecture.md wiki/Architecture.md
          cp docs/analyzers.md wiki/Analyzers.md
          cp README.md wiki/Home.md

      - name: Push to wiki
        run: |
          cd wiki
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add .
          git diff-index --quiet HEAD || git commit -m "Update wiki from ${{ github.sha }}"
          git push
```

**Documentation structure:**
```
docs/
├── architecture.md      # System design
├── analyzers.md         # Analyzer deep-dive
├── configuration.md     # Config guide
├── contributing.md      # Contribution guide
└── api-reference.md     # Auto-generated API docs
```

**Alternative: GitHub Pages (more flexible)**

If you prefer a full website over wiki:

```yaml
- uses: peaceiris/actions-gh-pages@v4
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    publish_dir: ./docs/_build
```

Then use MkDocs or Sphinx to build:
```yaml
- run: uv add --dev mkdocs-material
- run: uv run mkdocs build
```

**Estimated time:** 1 hour (+ time to write docs content)

---

## 10. Issue Auto-Labeler ⭐ LOW

**Purpose:** Automatically label issues and PRs based on content/files

**Files to create:**
- `.github/workflows/labeler.yml`
- `.github/labeler.yml`

**Configuration (.github/labeler.yml):**
```yaml
# Label PRs that modify analyzers
analyzer:
  - changed-files:
    - any-glob-to-any-file: 'src/tech_debtor/analyzers/**'

# Label PRs that modify reporters
reporter:
  - changed-files:
    - any-glob-to-any-file: 'src/tech_debtor/reporters/**'

# Label PRs that modify tests
tests:
  - changed-files:
    - any-glob-to-any-file: 'tests/**'

# Label PRs that modify documentation
documentation:
  - changed-files:
    - any-glob-to-any-file:
      - '*.md'
      - 'docs/**'

# Label PRs that modify dependencies
dependencies:
  - changed-files:
    - any-glob-to-any-file:
      - 'pyproject.toml'
      - 'uv.lock'

# Label PRs that modify CI
ci:
  - changed-files:
    - any-glob-to-any-file: '.github/**'
```

**Workflow:**
```yaml
name: Labeler
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  label:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/labeler@v5
```

**Create labels in GitHub:**
```bash
# Using GitHub CLI
gh label create "analyzer" --color "0052CC" --description "Changes to analyzers"
gh label create "reporter" --color "0052CC" --description "Changes to reporters"
gh label create "tests" --color "5319E7" --description "Test changes"
gh label create "documentation" --color "0075CA" --description "Documentation changes"
gh label create "dependencies" --color "0366D6" --description "Dependency updates"
gh label create "ci" --color "D4C5F9" --description "CI/CD changes"
```

**Estimated time:** 20 minutes

---

## 11. Stale Issue/PR Management ⭐ LOW

**Purpose:** Automatically close inactive issues after 60+14 days

**Files to create:**
- `.github/workflows/stale.yml`

**Configuration:**
```yaml
name: Close Stale Issues
on:
  schedule:
    - cron: '0 0 * * *'  # Run daily at midnight
  workflow_dispatch:  # Allow manual trigger

jobs:
  stale:
    runs-on: ubuntu-latest
    permissions:
      issues: write
      pull-requests: write
    steps:
      - uses: actions/stale@v9
        with:
          # Issues
          stale-issue-message: |
            This issue has been automatically marked as stale because it has not had
            recent activity. It will be closed in 14 days if no further activity occurs.

            If this issue is still relevant, please comment to keep it open.
          close-issue-message: |
            This issue was automatically closed due to inactivity.

            If you believe this is still relevant, please reopen or create a new issue.
          days-before-stale: 60
          days-before-close: 14
          stale-issue-label: 'stale'
          exempt-issue-labels: 'pinned,help-wanted,good-first-issue,bug'

          # Pull Requests
          stale-pr-message: |
            This PR has been automatically marked as stale because it has not had
            recent activity. It will be closed in 7 days if no further activity occurs.
          close-pr-message: |
            This PR was automatically closed due to inactivity.
          days-before-pr-stale: 30
          days-before-pr-close: 7
          stale-pr-label: 'stale'
          exempt-pr-labels: 'pinned,security,work-in-progress'

          # General
          operations-per-run: 100
          remove-stale-when-updated: true
```

**Create labels:**
```bash
gh label create "stale" --color "EEEEEE" --description "No recent activity"
gh label create "pinned" --color "D4C5F9" --description "Never mark as stale"
```

**Note:** This can be controversial. Consider:
- ✅ Keeps issue tracker clean
- ✅ Standard for large projects
- ❌ Can frustrate users
- ❌ May close valid issues

**Alternative approach:** Mark as stale but don't auto-close

**Estimated time:** 15 minutes

---

## 12. Type Integration Enhancement 🚀 ADVANCED

**Purpose:** Add mypy strict mode and integrate type issues as debt findings

**Current state:**
- Basic type hints exist
- No strict checking
- No integration with tech-debtor

**Implementation plan:**

### A. Enable strict mypy
```toml
# pyproject.toml
[tool.mypy]
python_version = "3.12"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_any_generics = true
```

### B. Add type annotations to all functions
```python
# Before
def analyze(file_path, source, tree, config):
    ...

# After
def analyze(
    file_path: str,
    source: str,
    tree: Tree,
    config: Config
) -> list[Finding]:
    ...
```

### C. Create TypeAnalyzer
```python
# src/tech_debtor/analyzers/types.py
class TypeAnalyzer:
    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]:
        # Run mypy programmatically
        result = mypy.api.run([file_path])

        # Parse mypy output
        findings = []
        for line in result[0].split('\n'):
            if 'error:' in line:
                # Extract location and message
                # Create Finding for each type error
                findings.append(Finding(
                    file_path=file_path,
                    line=line_num,
                    debt_type=DebtType.TYPE_ISSUE,
                    severity=Severity.MEDIUM,
                    message=f"Type error: {message}",
                    suggestion="Add type annotations",
                    remediation_minutes=10,
                ))
        return findings
```

### D. Add to models.py
```python
class DebtType(StrEnum):
    COMPLEXITY = "complexity"
    SMELL = "smell"
    DUPLICATION = "duplication"
    DEAD_CODE = "dead_code"
    CHURN = "churn"
    TYPE_ISSUE = "type_issue"  # NEW
```

**Estimated time:** 3-4 hours

---

## 13. CFG Analysis 🚀 ADVANCED

**Purpose:** Add control flow graph analyzer for unreachable code detection

**What CFG detects:**
- Unreachable code after return/raise
- Infinite loops
- Always-true/false conditions
- Missing return paths

**Implementation approach:**

### Option 1: Use existing library (easier)
```bash
uv add pycfg
```

```python
# src/tech_debtor/analyzers/cfg.py
import pycfg

class CFGAnalyzer:
    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]:
        cfg = pycfg.CFGBuilder().build_from_src(source)

        findings = []
        for node in cfg.nodes:
            if node.unreachable:
                findings.append(Finding(
                    file_path=file_path,
                    line=node.lineno,
                    debt_type=DebtType.DEAD_CODE,
                    severity=Severity.LOW,
                    message="Unreachable code detected",
                    suggestion="Remove unreachable code",
                    remediation_minutes=5,
                ))
        return findings
```

### Option 2: Build custom CFG (harder, more control)
```python
def _build_cfg(node: Node) -> dict:
    """Build control flow graph from AST node."""
    graph = {}

    for stmt in node.children:
        if stmt.type == 'if_statement':
            # Create branches
            then_block = stmt.child_by_field_name('consequence')
            else_block = stmt.child_by_field_name('alternative')
            graph[stmt] = [then_block, else_block]

        elif stmt.type == 'return_statement':
            # Terminal node
            graph[stmt] = []

        # ... handle other statement types

    return graph

def _find_unreachable(cfg: dict) -> list:
    """Find nodes that can't be reached from entry."""
    visited = set()

    def dfs(node):
        if node in visited:
            return
        visited.add(node)
        for child in cfg.get(node, []):
            dfs(child)

    dfs(entry_node)

    return [node for node in cfg if node not in visited]
```

**New debt type:**
```python
class DebtType(StrEnum):
    # ... existing
    UNREACHABLE_CODE = "unreachable_code"  # NEW
```

**Estimated time:** 6-8 hours (complex)

---

## 14. Data Flow Analysis 🚀 ADVANCED

**Purpose:** Track variable assignments and usage patterns

**What data flow detects:**
- Variables assigned but never read
- Variables read before assignment
- Unused function parameters
- Dead stores (reassigned before read)

**Implementation:**

```python
# src/tech_debtor/analyzers/dataflow.py

class DataFlowAnalyzer:
    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]:
        findings = []

        for func in tree_to_functions(tree.root_node):
            variables = self._analyze_function(func)

            # Find assigned but never read
            for var_name, info in variables.items():
                if info['assigned'] and not info['read']:
                    findings.append(Finding(
                        file_path=file_path,
                        line=info['line'],
                        debt_type=DebtType.DEAD_CODE,
                        severity=Severity.LOW,
                        message=f"Variable '{var_name}' assigned but never used",
                        suggestion=f"Remove unused variable '{var_name}'",
                        remediation_minutes=2,
                    ))

        return findings

    def _analyze_function(self, func_node: Node) -> dict:
        """Track variable lifetimes within function."""
        variables = {}

        # Walk AST
        for node in func_node.children:
            if node.type == 'assignment':
                # Track assignment
                var_name = self._get_target(node)
                variables[var_name] = {
                    'assigned': True,
                    'read': False,
                    'line': node.start_point[0] + 1
                }

            elif node.type == 'identifier':
                # Track usage
                var_name = node.text.decode()
                if var_name in variables:
                    variables[var_name]['read'] = True

        return variables
```

**Advanced features:**
- Track data flow across function boundaries
- Taint analysis (security)
- Null pointer detection

**Estimated time:** 8-10 hours (very complex)

---

## Implementation Timeline

### Week 1: Core Infrastructure
- [ ] Day 1: Test Suite Runner + Lint & Type Check (1 hour)
- [ ] Day 2: Security Scanning (1 hour)
- [ ] Day 3: Dependency Check (already done) + PyPI Setup (1 hour)

### Week 2: Automation
- [ ] Day 1: GitHub Releases + Release Notes (1.5 hours)
- [ ] Day 2: Self-Analysis Report (2 hours)
- [ ] Day 3: Documentation Generation (1 hour)

### Week 3: Community
- [ ] Day 1: Issue Auto-Labeler + Stale workflow (0.5 hour)
- [ ] Day 2-3: Buffer for fixes

### Week 4+: Advanced Features (Optional)
- [ ] Type Integration (3-4 hours)
- [ ] CFG Analysis (6-8 hours)
- [ ] Data Flow Analysis (8-10 hours)

**Total estimated time:**
- Phase 1 (Core + Automation): ~8-10 hours
- Phase 2 (Advanced features): ~20-25 hours

---

## Quick Start Checklist

Before implementing workflows:
- [ ] Enable GitHub Actions in repo settings
- [ ] Create PyPI account with 2FA
- [ ] Sign up for Codecov (for coverage)
- [ ] Enable CodeQL in repo settings
- [ ] Create required labels (using `gh label create`)
- [ ] Initialize GitHub Wiki (create one page manually)
- [ ] Add `GITHUB_TOKEN` permissions to repo settings

---

## Notes

**Security priorities:**
1. Use trusted publishing for PyPI (no tokens)
2. Enable CodeQL + pip-audit minimum
3. Add Bandit for Python-specific checks
4. Never commit secrets to git
5. Use GitHub Environments with required reviewers

**Dependency management:**
- Current versions are all up-to-date ✅
- Keep flexible version constraints (current approach is good)
- Use Dependabot or weekly checks for updates
- Test thoroughly after upgrades

**Documentation:**
- GitHub Wiki is simpler for getting started
- GitHub Pages is better for complex docs with search
- Both can be auto-generated from `docs/` directory

**Advanced analyzers:**
- Start with type integration (easier, immediate value)
- CFG is valuable but complex
- Data flow has diminishing returns (overlap with dead code)
- Consider: Do users want these features?
