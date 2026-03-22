"""Rich terminal reporter for certificate analysis."""
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..models import CertReport, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_report(report: CertReport, console: Optional[Console] = None):
    console = console or Console()
    grade_color = {
        "A": "green", "B": "blue", "C": "yellow",
        "D": "red", "F": "red bold",
    }.get(report.grade, "white")
    console.print(Panel(
        f"[bold]Certificates:[/] {report.total_certs}\n"
        f"[bold]Valid:[/] [green]{report.valid_count}[/] | "
        f"[bold]Expiring Soon:[/] [yellow]{report.expiring_soon_count}[/] | "
        f"[bold]Expired:[/] [red]{report.expired_count}[/]\n"
        f"[bold]Health Score:[/] [{grade_color}]"
        f"{report.health_score:.1f}/100 (Grade {report.grade})[/]\n"
        f"[bold]Findings:[/] {len(report.findings)} "
        f"(🔴 {report.critical_count} 🟠 {report.high_count} "
        f"🟡 {report.medium_count} 🔵 {report.low_count} ⚪ {report.info_count})",
        title="🔒 Certificate Watch Report",
        border_style=grade_color,
    ))
    if not report.findings:
        console.print("[green]✅ All certificates are healthy![/]")
        return
    table = Table(title="Findings", show_lines=True)
    table.add_column("Rule", style="bold", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Domain", width=30)
    table.add_column("Issue", width=45)
    table.add_column("Recommendation", width=40)
    for f in report.findings:
        sev_style = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            f.rule_id,
            f"[{sev_style}]{f.severity.value.upper()}[/]",
            f"{f.domain}\n({f.environment})",
            f.description,
            f.recommendation,
        )
    console.print(table)
