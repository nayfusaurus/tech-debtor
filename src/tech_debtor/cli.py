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
