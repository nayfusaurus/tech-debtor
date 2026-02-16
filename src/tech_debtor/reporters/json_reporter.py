from __future__ import annotations

import json

from tech_debtor.models import ProjectReport
from tech_debtor.scoring import prioritize_findings


def render_json(report: ProjectReport, churn: dict[str, int]) -> str:
    findings = prioritize_findings(report.all_findings, churn)

    data = {
        "debt_score": report.debt_score,
        "debt_rating": report.debt_rating,
        "total_files": report.total_files,
        "total_findings": report.total_findings,
        "total_remediation_minutes": report.total_remediation_minutes,
        "sqale_index_minutes": report.sqale_index_minutes,
        "sqale_index_hours": round(report.sqale_index_minutes / 60, 2),
        "technical_debt_ratio": round(report.technical_debt_ratio, 2),
        "sqale_rating": report.sqale_rating,
        "findings": [
            {
                "file_path": f.file_path,
                "line": f.line,
                "end_line": f.end_line,
                "debt_type": f.debt_type.value,
                "severity": f.severity.name.lower(),
                "message": f.message,
                "suggestion": f.suggestion,
                "remediation_minutes": f.remediation_minutes,
                "symbol": f.symbol,
            }
            for f in findings
        ],
    }
    return json.dumps(data, indent=2)
