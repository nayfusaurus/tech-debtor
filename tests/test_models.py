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
