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
    file_report = FileReport(
        file_path="src/foo.py", lines_of_code=200, findings=[finding]
    )
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
    assert (
        "No findings" in captured.out
        or "Excellent" in captured.out
        or "0" in captured.out
    )
