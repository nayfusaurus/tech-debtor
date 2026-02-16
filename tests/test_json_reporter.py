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
    file_report = FileReport(
        file_path="src/foo.py", lines_of_code=200, findings=[finding]
    )
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
