"""
CLI Entrypoint — cmmc_scope/main.py
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from cmmc_scope import __version__
from cmmc_scope.collectors.aws import collect_iam_mfa_status, collect_cloudtrail_status
from cmmc_scope.collectors.github import collect_branch_protection
from cmmc_scope.engine import (
    ComplianceStatus,
    Finding,
    evaluate_branch_protection,
    evaluate_cloudtrail,
    evaluate_iam_mfa,
    evaluate_stale_accounts,
)
from cmmc_scope.reporter import generate_all_reports, generate_json_report, generate_pdf_report

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("cmmc_scope")

app = typer.Typer(
    name="cmmc-scope",
    help="CMMC-Scope: Automated CMMC Level 2 / NIST SP 800-171 compliance auditor.",
    add_completion=False,
    rich_markup_mode="rich",
)

audit_app = typer.Typer(
    name="audit",
    help="Run one or more CMMC compliance checks.",
    rich_markup_mode="rich",
)
app.add_typer(audit_app, name="audit")

console = Console()
err_console = Console(stderr=True, style="bold red")

_OUTPUT_DIR_OPTION = typer.Option(
    "./cmmc_evidence",
    "--output-dir", "-o",
    help="Directory where evidence files will be written.",
    show_default=True,
)

_FORMAT_OPTION = typer.Option(
    "both",
    "--format", "-f",
    help="Output format: 'json', 'pdf', or 'both'.",
    show_default=True,
)

_VERBOSE_OPTION = typer.Option(
    False,
    "--verbose", "-v",
    help="Enable DEBUG-level logging.",
)

_STATUS_EMOJI: dict[ComplianceStatus, str] = {
    ComplianceStatus.PASS: "✅",
    ComplianceStatus.FAIL: "❌",
    ComplianceStatus.ERROR: "⚠️",
    ComplianceStatus.NOT_APPLICABLE: "-",
}

_STATUS_STYLE: dict[ComplianceStatus, str] = {
    ComplianceStatus.PASS: "bold green",
    ComplianceStatus.FAIL: "bold red",
    ComplianceStatus.ERROR: "bold yellow",
    ComplianceStatus.NOT_APPLICABLE: "dim",
}


def _set_verbosity(verbose: bool) -> None:
    if verbose:
        logging.getLogger("cmmc_scope").setLevel(logging.DEBUG)


def _print_findings_table(findings: list[Finding]) -> None:
    table = Table(
        title="CMMC-Scope Audit Results",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold white on dark_blue",
    )
    table.add_column("CMMC ID", style="bold cyan", no_wrap=True)
    table.add_column("Control Title", style="white")
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Scope", style="dim")
    table.add_column("Summary")

    for f in findings:
        status_str = f"{_STATUS_EMOJI[f.status]}  {f.status.value}"
        table.add_row(
            f.cmmc_practice_id,
            f.control_title,
            f"[{_STATUS_STYLE[f.status]}]{status_str}[/]",
            f.resource_scope,
            f.summary,
        )

    console.print()
    console.print(table)


def _write_reports(findings: list[Finding], output_dir: Path, fmt: str) -> None:
    fmt = fmt.lower()
    output_dir = Path(output_dir)

    if fmt == "both":
        paths = generate_all_reports(findings, output_dir)
        console.print(f"\n[bold green]Evidence written:[/bold green]")
        for kind, path in paths.items():
            console.print(f"  [{kind.upper()}] {path}")
    elif fmt == "json":
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = generate_json_report(findings, output_dir / f"cmmc_scope_evidence_{ts}.json")
        console.print(f"\n[bold green]Evidence written:[/bold green]  [JSON] {path}")
    elif fmt == "pdf":
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = generate_pdf_report(findings, output_dir / f"cmmc_scope_evidence_{ts}.pdf")
        console.print(f"\n[bold green]Evidence written:[/bold green]  [PDF] {path}")
    else:
        err_console.print(f"Unknown format '{fmt}'. Choose from: json, pdf, both.")
        raise typer.Exit(code=1)


def _exit_code_for_findings(findings: list[Finding]) -> int:
    statuses = {f.status for f in findings}
    if ComplianceStatus.FAIL in statuses:
        return 2
    if ComplianceStatus.ERROR in statuses:
        return 3
    return 0


@app.command("version")
def cmd_version() -> None:
    """Print the CMMC-Scope version and exit."""
    console.print(
        Panel(
            f"[bold cyan]CMMC-Scope[/bold cyan] v[bold]{__version__}[/bold]\n"
            "Automated CMMC Level 2 / NIST SP 800-171 Compliance Auditor",
            expand=False,
        )
    )


@audit_app.command("aws")
def cmd_audit_aws(
    profile: Optional[str] = typer.Option(None, "--profile", "-p"),
    region: str = typer.Option("us-east-1", "--region", "-r", show_default=True),
    output_dir: Path = _OUTPUT_DIR_OPTION,
    fmt: str = _FORMAT_OPTION,
    verbose: bool = _VERBOSE_OPTION,
) -> None:
    """Run all AWS checks: IA.L2-3.5.3, AC.L2-3.1.1, AU.L2-3.3.1."""
    _set_verbosity(verbose)

    console.print(
        Panel(
            "[bold]CMMC-Scope[/bold] - Audit - AWS\n"
            "[cyan]Controls:[/cyan] IA.L2-3.5.3 (MFA) + AC.L2-3.1.1 (Stale Accounts) + AU.L2-3.3.1 (CloudTrail)",
            expand=False,
        )
    )

    with console.status("[bold green]Collecting IAM credential report..."):
        iam_raw = collect_iam_mfa_status(profile_name=profile, region_name=region)

    with console.status("[bold green]Collecting CloudTrail status..."):
        ct_raw = collect_cloudtrail_status(profile_name=profile, region_name=region)

    findings = [
        evaluate_iam_mfa(iam_raw),
        evaluate_stale_accounts(iam_raw),
        evaluate_cloudtrail(ct_raw),
    ]

    _print_findings_table(findings)
    _write_reports(findings, output_dir, fmt)

    exit_code = _exit_code_for_findings(findings)
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@audit_app.command("github")
def cmd_audit_github(
    repo: str = typer.Option(..., "--repo"),
    token: Optional[str] = typer.Option(None, "--token", "-t"),
    branch: Optional[str] = typer.Option(None, "--branch", "-b"),
    output_dir: Path = _OUTPUT_DIR_OPTION,
    fmt: str = _FORMAT_OPTION,
    verbose: bool = _VERBOSE_OPTION,
) -> None:
    """Run CM.L2-3.4.1 (Branch Protection) check."""
    _set_verbosity(verbose)

    resolved_token = token or os.environ.get("GITHUB_TOKEN", "")
    if not resolved_token:
        err_console.print("No GitHub token provided. Use --token or set GITHUB_TOKEN.")
        raise typer.Exit(code=1)

    console.print(
        Panel(
            f"[bold]CMMC-Scope[/bold] - Audit - GitHub\n"
            f"[cyan]Control:[/cyan] CM.L2-3.4.1 - Baseline Configuration & Change Control\n"
            f"[cyan]Repository:[/cyan] {repo}",
            expand=False,
        )
    )

    with console.status("[bold green]Collecting branch protection data..."):
        raw = collect_branch_protection(
            github_token=resolved_token,
            repo_full_name=repo,
            branch_name=branch,
        )

    findings = [evaluate_branch_protection(raw)]
    _print_findings_table(findings)
    _write_reports(findings, output_dir, fmt)

    exit_code = _exit_code_for_findings(findings)
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@audit_app.command("all")
def cmd_audit_all(
    repo: str = typer.Option(..., "--repo"),
    token: Optional[str] = typer.Option(None, "--token", "-t"),
    branch: Optional[str] = typer.Option(None, "--branch", "-b"),
    aws_profile: Optional[str] = typer.Option(None, "--aws-profile"),
    aws_region: str = typer.Option("us-east-1", "--aws-region", show_default=True),
    output_dir: Path = _OUTPUT_DIR_OPTION,
    fmt: str = _FORMAT_OPTION,
    verbose: bool = _VERBOSE_OPTION,
) -> None:
    """Run all implemented CMMC checks and produce a combined evidence package."""
    _set_verbosity(verbose)

    resolved_token = token or os.environ.get("GITHUB_TOKEN", "")
    if not resolved_token:
        err_console.print("No GitHub token provided. Use --token or set GITHUB_TOKEN.")
        raise typer.Exit(code=1)

    console.print(
        Panel(
            "[bold]CMMC-Scope[/bold] - Audit - All Controls\n"
            "Running: IA.L2-3.5.3 + AC.L2-3.1.1 + AU.L2-3.3.1 + CM.L2-3.4.1",
            expand=False,
        )
    )

    findings: list[Finding] = []

    with console.status("[bold green][1/3] Collecting IAM credential report..."):
        iam_raw = collect_iam_mfa_status(
            profile_name=aws_profile, region_name=aws_region
        )
    findings.append(evaluate_iam_mfa(iam_raw))
    findings.append(evaluate_stale_accounts(iam_raw))

    with console.status("[bold green][2/3] Collecting CloudTrail status..."):
        ct_raw = collect_cloudtrail_status(
            profile_name=aws_profile, region_name=aws_region
        )
    findings.append(evaluate_cloudtrail(ct_raw))

    with console.status("[bold green][3/3] Collecting GitHub branch protection data..."):
        gh_raw = collect_branch_protection(
            github_token=resolved_token,
            repo_full_name=repo,
            branch_name=branch,
        )
    findings.append(evaluate_branch_protection(gh_raw))

    _print_findings_table(findings)
    _write_reports(findings, output_dir, fmt)

    exit_code = _exit_code_for_findings(findings)
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


def main() -> None:
    app()


if __name__ == "__main__":
    main()