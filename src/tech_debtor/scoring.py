from __future__ import annotations

from tech_debtor.models import Finding


def _priority_key(finding: Finding, churn: dict[str, int]) -> tuple[float, ...]:
    churn_count = churn.get(finding.file_path, 0)
    return (
        -finding.severity,
        -churn_count,
        finding.remediation_minutes,
    )


def prioritize_findings(
    findings: list[Finding],
    churn: dict[str, int],
) -> list[Finding]:
    return sorted(findings, key=lambda f: _priority_key(f, churn))
