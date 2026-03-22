"""CLI entry point for cert-watch."""
import sys

import click
from rich.console import Console
from rich.table import Table

from .analyzers.cert_analyzer import analyze_certificates
from .demo import get_demo_inventory
from .models import CERT_RULES
from .parser import parse_inventory
from .reporters.export_reporter import to_html, to_json
from .reporters.terminal_reporter import print_report

console = Console()


@click.group()
def cli():
    """🔒 cert-watch — TLS/SSL certificate expiry scanner."""
    pass


@cli.command()
@click.argument("inventory_file", type=click.Path(exists=True))
@click.option(
    "--format", "fmt",
    type=click.Choice(["terminal", "json", "html"]),
    default="terminal",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default=None,
)
@click.option("--output", "-o", type=click.Path(), default=None)
def scan(inventory_file, fmt, fail_on, output):
    """Scan certificate inventory for issues."""
    with open(inventory_file, "r") as f:
        content = f.read()
    certs = parse_inventory(content)
    report = analyze_certificates(certs)
    _output_report(report, fmt, output)
    if fail_on:
        severity_order = ["critical", "high", "medium", "low"]
        threshold = severity_order.index(fail_on)
        for finding in report.findings:
            if severity_order.index(finding.severity.value) <= threshold:
                sys.exit(1)


@cli.command()
@click.option(
    "--format", "fmt",
    type=click.Choice(["terminal", "json", "html"]),
    default="terminal",
)
def demo(fmt):
    """Run demo with sample certificate inventory."""
    content = get_demo_inventory()
    certs = parse_inventory(content)
    report = analyze_certificates(certs)
    _output_report(report, fmt, None)


@cli.command()
def rules():
    """List all certificate validation rules."""
    table = Table(title="Certificate Validation Rules", show_lines=True)
    table.add_column("Rule ID", style="bold", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=35)
    table.add_column("Description", width=50)
    for rule_id, rule in CERT_RULES.items():
        sev_colors = {
            "critical": "red bold", "high": "red",
            "medium": "yellow", "low": "cyan",
        }
        color = sev_colors.get(rule["severity"].value, "white")
        table.add_row(
            rule_id,
            f"[{color}]{rule['severity'].value.upper()}[/]",
            rule["title"],
            rule["description"],
        )
    console.print(table)


def _output_report(report, fmt, output):
    if fmt == "json":
        result = to_json(report)
        if output:
            with open(output, "w") as f:
                f.write(result)
            console.print(f"[green]Report saved to {output}[/]")
        else:
            console.print(result)
    elif fmt == "html":
        result = to_html(report)
        if output:
            with open(output, "w") as f:
                f.write(result)
            console.print(f"[green]Report saved to {output}[/]")
        else:
            console.print(result)
    else:
        print_report(report, console)


if __name__ == "__main__":
    cli()
