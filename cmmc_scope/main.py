"""
CLI Entrypoint — cmmc_scope/main.py

Provides the ``cmmc-scope`` command-line interface built on Typer.

Commands
--------
  cmmc-scope audit aws          Run IA.L2-3.5.3 (MFA) check against AWS IAM
  cmmc-scope audit github       Run CM.L2-3.4.1 (Branch Protection) check
  cmmc-scope audit all          Run every check and produce a combined report
  cmmc-scope version            Print tool version and exit

Usage examples
--------------
  cmmc-scope audit aws --output-dir ./evidence
  cmmc-scope audit aws --profile my-profile --region eu-west-1
  cmmc-scope audit github --repo acme/my-service --token ghp_...
  cmmc-scope audit all --repo acme/my-service --output-dir ./evidence
  cmmc-scope audit all --format pdf
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from cmmc_scope import __version__
from cmmc_scope.collectors.aws import collect_iam_mfa_status
from cmmc_scope.collectors.github import collect_branch_protection
from cmmc_scope.engine import (
    ComplianceStatus,
    Finding,
    evaluate_branch_protection,
    evaluate_iam_mfa,
)
from cmmc_scope.reporter import generate_all_reports, generate_json_report, generate_pdf_report

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("cmmc_scope")

# ---------------------------------------------------------------------------
# Typer application tree
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="cmmc-scope",
    help=(
        "CMMC-Scope: Automated CMMC Level 2 / NIST SP 800-171 compliance auditor "
        "for cloud and developer environments.\n\n"
        "Generates immutable, auditor-ready evidence packages (JSON + PDF)."
    ),
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

# ---------------------------------------------------------------------------
# Shared option types (re-used across commands)
# ---------------------------------------------------------------------------

_OUTPUT_DIR_OPTION = typer.Option(
    "./cmmc_evidence",
    "--output-dir", "-o",
    help="Directory where evidence files (JSON / PDF) will be written.",
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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_STATUS_EMOJI: dict[ComplianceStatus, str] = {
    ComplianceStatus.PASS: "✅",
    ComplianceStatus.FAIL: "❌",
    ComplianceStatus.ERROR: "⚠️",
    ComplianceStatus.NOT_APPLICABLE: "—",
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
        logging.getLogger("botocore").setLevel(logging.INFO)
        logging.getLogger("github").setLevel(logging.INFO)


def _print_findings_table(findings: list[Finding]) -> None:
    """Render a Rich summary table of all findings to stdout."""
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


def _write_reports(
    findings: list[Finding],
    output_dir: Path,
    fmt: str,
) -> None:
    """Write evidence files in the requested format(s)."""
    fmt = fmt.lower()
    output_dir = Path(output_dir)

    if fmt == "both":
        paths = generate_all_reports(findings, output_dir)
        console.print(f"\n[bold green]Evidence written:[/bold green]")
        for kind, path in paths.items():
            console.print(f"  [{kind.upper()}] {path}")

    elif fmt == "json":
        from cmmc_scope.reporter import generate_json_report
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = generate_json_report(findings, output_dir / f"cmmc_scope_evidence_{ts}.json")
        console.print(f"\n[bold green]Evidence written:[/bold green]  [JSON] {path}")

    elif fmt == "pdf":
        from cmmc_scope.reporter import generate_pdf_report
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = generate_pdf_report(findings, output_dir / f"cmmc_scope_evidence_{ts}.pdf")
        console.print(f"\n[bold green]Evidence written:[/bold green]  [PDF] {path}")

    else:
        err_console.print(f"Unknown format '{fmt}'. Choose from: json, pdf, both.")
        raise typer.Exit(code=1)


def _exit_code_for_findings(findings: list[Finding]) -> int:
    """Return exit code 2 if any finding FAILed, 3 if any ERRORed, else 0."""
    statuses = {f.status for f in findings}
    if ComplianceStatus.FAIL in statuses:
        return 2
    if ComplianceStatus.ERROR in statuses:
        return 3
    return 0


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


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
    profile: Optional[str] = typer.Option(
        None,
        "--profile", "-p",
        help="AWS CLI named profile.  Omit to use the default credential chain.",
    ),
    region: str = typer.Option(
        "us-east-1",
        "--region", "-r",
        help="AWS region for the boto3 session.",
        show_default=True,
    ),
    output_dir: Path = _OUTPUT_DIR_OPTION,
    fmt: str = _FORMAT_OPTION,
    verbose: bool = _VERBOSE_OPTION,
) -> None:
    """
    [bold]IA.L2-3.5.3[/bold] — Audit AWS IAM for users with console access but no MFA.

    Fetches the IAM Credential Report and flags every active IAM user whose
    [italic]mfa_active[/italic] field is false.

    Exits with code 2 if the control FAILS, 3 on collection errors, 0 on PASS.
    """
    _set_verbosity(verbose)

    console.print(
        Panel(
            "[bold]CMMC-Scope[/bold] › Audit › AWS\n"
            "[cyan]Control:[/cyan] IA.L2-3.5.3 — Multi-Factor Authentication",
            expand=False,
        )
    )

    with console.status("[bold green]Collecting IAM credential report from AWS…"):
        raw = collect_iam_mfa_status(profile_name=profile, region_name=region)

    with console.status("[bold green]Evaluating findings against CMMC IA.L2-3.5.3…"):
        finding = evaluate_iam_mfa(raw)

    findings = [finding]
    _print_findings_table(findings)
    _write_reports(findings, output_dir, fmt)

    exit_code = _exit_code_for_findings(findings)
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@audit_app.command("github")
def cmd_audit_github(
    repo: str = typer.Option(
        ...,
        "--repo",
        help="Full repository name in owner/repo format, e.g. acme-corp/my-service.",
    ),
    token: Optional[str] = typer.Option(
        None,
        "--token", "-t",
        help=(
            "GitHub Personal Access Token.  "
            "If omitted, the GITHUB_TOKEN environment variable is used."
        ),
    ),
    branch: Optional[str] = typer.Option(
        None,
        "--branch", "-b",
        help="Branch to inspect.  Defaults to the repository's default branch.",
    ),
    output_dir: Path = _OUTPUT_DIR_OPTION,
    fmt: str = _FORMAT_OPTION,
    verbose: bool = _VERBOSE_OPTION,
) -> None:
    """
    [bold]CM.L2-3.4.1[/bold] — Audit a GitHub repository's branch protection rules.

    Verifies that the target branch requires at least one approving pull-request
    review before code can be merged into the protected branch.

    Exits with code 2 if the control FAILS, 3 on collection errors, 0 on PASS.
    """
    _set_verbosity(verbose)

    resolved_token = token or os.environ.get("GITHUB_TOKEN", "")
    if not resolved_token:
        err_console.print(
            "No GitHub token provided.  "
            "Use --token or set the GITHUB_TOKEN environment variable."
        )
        raise typer.Exit(code=1)

    console.print(
        Panel(
            "[bold]CMMC-Scope[/bold] › Audit › GitHub\n"
            "[cyan]Control:[/cyan] CM.L2-3.4.1 — Baseline Configuration & Change Control\n"
            f"[cyan]Repository:[/cyan] {repo}"
            + (f"  [cyan]Branch:[/cyan] {branch}" if branch else ""),
            expand=False,
        )
    )

    with console.status("[bold green]Collecting branch protection data from GitHub…"):
        raw = collect_branch_protection(
            github_token=resolved_token,
            repo_full_name=repo,
            branch_name=branch,
        )

    with console.status("[bold green]Evaluating findings against CMMC CM.L2-3.4.1…"):
        finding = evaluate_branch_protection(raw)

    findings = [finding]
    _print_findings_table(findings)
    _write_reports(findings, output_dir, fmt)

    exit_code = _exit_code_for_findings(findings)
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@audit_app.command("all")
def cmd_audit_all(
    repo: str = typer.Option(
        ...,
        "--repo",
        help="Full GitHub repository name (owner/repo) for the CM.L2-3.4.1 check.",
    ),
    token: Optional[str] = typer.Option(
        None,
        "--token", "-t",
        help="GitHub PAT.  Falls back to GITHUB_TOKEN env var.",
    ),
    branch: Optional[str] = typer.Option(
        None,
        "--branch", "-b",
        help="GitHub branch to inspect.  Defaults to the repository default.",
    ),
    aws_profile: Optional[str] = typer.Option(
        None,
        "--aws-profile",
        help="AWS CLI named profile for the IA.L2-3.5.3 check.",
    ),
    aws_region: str = typer.Option(
        "us-east-1",
        "--aws-region",
        help="AWS region for the boto3 session.",
        show_default=True,
    ),
    output_dir: Path = _OUTPUT_DIR_OPTION,
    fmt: str = _FORMAT_OPTION,
    verbose: bool = _VERBOSE_OPTION,
) -> None:
    """
    Run [bold]all[/bold] implemented CMMC checks and produce a combined evidence package.

    Executes both IA.L2-3.5.3 (AWS MFA) and CM.L2-3.4.1 (GitHub branch
    protection) in sequence and combines results into a single report.

    Exits with code 2 if any control FAILS, 3 on any collection error, 0 if all PASS.
    """
    _set_verbosity(verbose)

    resolved_token = token or os.environ.get("GITHUB_TOKEN", "")
    if not resolved_token:
        err_console.print(
            "No GitHub token provided.  "
            "Use --token or set the GITHUB_TOKEN environment variable."
        )
        raise typer.Exit(code=1)

    console.print(
        Panel(
            "[bold]CMMC-Scope[/bold] › Audit › All Controls\n"
            "Running: IA.L2-3.5.3 (AWS MFA) + CM.L2-3.4.1 (GitHub Branch Protection)",
            expand=False,
        )
    )

    findings: list[Finding] = []

    # ── AWS MFA ──────────────────────────────────────────────────────────────
    with console.status("[bold green][1/2] Collecting IAM credential report…"):
        aws_raw = collect_iam_mfa_status(
            profile_name=aws_profile, region_name=aws_region
        )
    with console.status("[bold green][1/2] Evaluating IA.L2-3.5.3…"):
        findings.append(evaluate_iam_mfa(aws_raw))

    # ── GitHub Branch Protection ─────────────────────────────────────────────
    with console.status("[bold green][2/2] Collecting GitHub branch protection data…"):
        gh_raw = collect_branch_protection(
            github_token=resolved_token,
            repo_full_name=repo,
            branch_name=branch,
        )
    with console.status("[bold green][2/2] Evaluating CM.L2-3.4.1…"):
        findings.append(evaluate_branch_protection(gh_raw))

    _print_findings_table(findings)
    _write_reports(findings, output_dir, fmt)

    exit_code = _exit_code_for_findings(findings)
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:  # pragma: no cover
    """Package entrypoint called by the ``cmmc-scope`` console script."""
    app()


if __name__ == "__main__":
    main()
