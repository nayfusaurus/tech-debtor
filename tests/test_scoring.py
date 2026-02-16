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
    assert result[0].file_path == "b.py"
