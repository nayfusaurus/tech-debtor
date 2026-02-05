from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class DebtType(StrEnum):
    COMPLEXITY = "complexity"
    SMELL = "smell"
    DUPLICATION = "duplication"
    DEAD_CODE = "dead_code"
    CHURN = "churn"


@dataclass(frozen=True)
class Finding:
    file_path: str
    line: int
    end_line: int
    debt_type: DebtType
    severity: Severity
    message: str
    suggestion: str
    remediation_minutes: int
    symbol: str | None = None


@dataclass
class FileReport:
    file_path: str
    lines_of_code: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def total_remediation_minutes(self) -> int:
        return sum(f.remediation_minutes for f in self.findings)

    @property
    def finding_count(self) -> int:
        return len(self.findings)


@dataclass
class ProjectReport:
    file_reports: list[FileReport] = field(default_factory=list)
    cost_per_line: float = 0.5

    @property
    def all_findings(self) -> list[Finding]:
        return [f for r in self.file_reports for f in r.findings]

    @property
    def total_lines(self) -> int:
        return sum(r.lines_of_code for r in self.file_reports)

    @property
    def total_remediation_minutes(self) -> int:
        return sum(r.total_remediation_minutes for r in self.file_reports)

    @property
    def total_files(self) -> int:
        return len(self.file_reports)

    @property
    def total_findings(self) -> int:
        return sum(r.finding_count for r in self.file_reports)

    @property
    def debt_score(self) -> int:
        if self.total_lines == 0:
            return 0
        raw = (self.total_remediation_minutes / (self.total_lines * self.cost_per_line)) * 100
        return min(100, int(raw))

    @property
    def debt_rating(self) -> str:
        score = self.debt_score
        if score <= 20:
            return "Excellent"
        if score <= 40:
            return "Good"
        if score <= 60:
            return "Fair"
        if score <= 80:
            return "Poor"
        return "Critical"
