from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from tech_debtor.models import ProjectReport, Severity, DebtType
from tech_debtor.scoring import prioritize_findings

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}

DEBT_TYPE_LABELS = {
    DebtType.COMPLEXITY: "COMPLEXITY",
    DebtType.SMELL: "SMELL",
    DebtType.DUPLICATION: "DUPLICATION",
    DebtType.DEAD_CODE: "DEAD CODE",
    DebtType.CHURN: "CHURN",
    DebtType.EXCEPTION: "EXCEPTION",
    DebtType.SECURITY: "SECURITY",
}

RATING_COLORS = {
    "Excellent": "bold green",
    "Good": "green",
    "Fair": "yellow",
    "Poor": "red",
    "Critical": "bold red",
}


SQALE_RATING_COLORS = {
    "A": "bright_green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "E": "bright_red",
}

SQALE_RATING_LABELS = {
    "A": "Excellent",
    "B": "Good",
    "C": "Fair",
    "D": "Poor",
    "E": "Critical",
}


def render_terminal(
    report: ProjectReport,
    churn: dict[str, int],
    console: Console | None = None,
    filtered: bool = False,
) -> None:
    console = console or Console()
    findings = prioritize_findings(report.all_findings, churn)

    # Header
    console.print(f"\n[bold]tech-debtor[/bold] — scanned {report.total_files} files\n")

    if not findings:
        console.print("[green]No findings — code looks clean![/green]\n")

    # Findings
    for f in findings:
        color = SEVERITY_COLORS.get(f.severity, "white")
        label = DEBT_TYPE_LABELS.get(f.debt_type, f.debt_type.value.upper())
        location = f"{f.file_path}:{f.line}"
        if f.symbol:
            location += f":{f.symbol}"

        console.print(f" [{color}]{label}[/{color}]  {location}")
        console.print(f"   {f.message}")
        console.print(f"   [dim]→ {f.suggestion}[/dim]")
        console.print(f"   [dim]Remediation: ~{f.remediation_minutes} min | Severity: {f.severity.name.lower()}[/dim]\n")

    # Summary
    score = report.debt_score
    rating = report.debt_rating
    rating_color = RATING_COLORS.get(rating, "white")
    total_minutes = report.total_remediation_minutes
    hours = total_minutes / 60

    severity_counts = {s: 0 for s in Severity}
    for f in findings:
        severity_counts[f.severity] += 1
    counts_str = ", ".join(
        f"{count} {sev.name.lower()}" for sev, count in sorted(severity_counts.items(), reverse=True) if count > 0
    )

    console.rule()
    console.print(f" Debt Score: [{rating_color}]{score}/100 ({rating})[/{rating_color}]")
    console.print(f" Total items: {len(findings)} ({counts_str})")
    console.print(f" Est. remediation: ~{hours:.0f} hours" if hours >= 1 else f" Est. remediation: ~{total_minutes} min")

    # Hotspots (top 3 churned files with findings)
    if churn:
        file_churn: dict[str, int] = {}
        for f in findings:
            c = churn.get(f.file_path, 0)
            if c > 0:
                file_churn[f.file_path] = max(file_churn.get(f.file_path, 0), c)
        if file_churn:
            hotspots = sorted(file_churn, key=file_churn.get, reverse=True)[:3]  # type: ignore[arg-type]
            console.print(f" Hotspots: {', '.join(hotspots)}")
    console.rule()

    # SQALE Metrics panel
    sqale_hours = report.sqale_index_minutes / 60
    rating = report.sqale_rating
    rating_color = SQALE_RATING_COLORS.get(rating, "white")
    rating_label = SQALE_RATING_LABELS.get(rating, "")

    panel_text = (
        f"[bold cyan]SQALE Index:[/bold cyan] {sqale_hours:.1f} hours ({report.sqale_index_minutes} min)\n"
        f"[bold cyan]Technical Debt Ratio:[/bold cyan] {report.technical_debt_ratio:.1f}%\n"
        f"[bold cyan]SQALE Rating:[/bold cyan] [{rating_color}]{rating}[/{rating_color}] ({rating_label})"
    )
    if filtered:
        panel_text += "\n[dim](filtered: metrics reflect selected checks only)[/dim]"

    console.print(Panel(
        panel_text,
        title="SQALE Metrics",
        border_style="cyan",
    ))
    console.print()
