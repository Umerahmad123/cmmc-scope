"""
Evaluation Engine — cmmc_scope/engine.py

This module is the compliance brain of CMMC-Scope.  It accepts raw data
from the collector modules and applies deterministic pass/fail logic to
produce structured Finding objects that are mapped to official CMMC / NIST
SP 800-171 control identifiers.

Design invariants:
  - No I/O occurs here (no boto3, no GitHub calls, no file writes).
  - All functions are pure: same inputs → same outputs.
  - Every Finding carries enough context for an auditor to reproduce the check.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Sequence

from cmmc_scope.collectors.aws import CredentialReportResult, IamUserMfaRecord
from cmmc_scope.collectors.github import BranchProtectionResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core domain types
# ---------------------------------------------------------------------------


class ComplianceStatus(str, Enum):
    """Tri-state compliance result aligned with CMMC assessment terminology."""

    PASS = "PASS"          # Control objective is met.
    FAIL = "FAIL"          # Control objective is NOT met.
    ERROR = "ERROR"        # Collection or evaluation could not complete.
    NOT_APPLICABLE = "N/A" # Control is not applicable to the scoped environment.


@dataclass
class Finding:
    """
    A single, atomic compliance finding tied to one CMMC control.

    This is the primary data structure emitted by the engine and consumed by
    reporter.py.  All fields are intentionally primitive-typed so the object
    is trivially JSON-serialisable.
    """

    # ── CMMC / NIST identifiers ──────────────────────────────────────────────
    cmmc_practice_id: str       # e.g. "IA.L2-3.5.3"
    nist_control_id: str        # e.g. "3.5.3"
    control_family: str         # e.g. "Identification & Authentication"
    control_title: str          # Short human-readable title

    # ── Evaluation result ────────────────────────────────────────────────────
    status: ComplianceStatus
    summary: str                # One-sentence plain-English verdict

    # ── Evidence detail ──────────────────────────────────────────────────────
    # Each string in `evidence` is one discrete, auditor-visible data point.
    evidence: list[str] = field(default_factory=list)

    # Items the auditor must remediate to achieve compliance.
    remediation_items: list[str] = field(default_factory=list)

    # ── Provenance ───────────────────────────────────────────────────────────
    evaluated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    resource_scope: str = ""    # e.g. "AWS Account 123456789012"


# ---------------------------------------------------------------------------
# Control metadata constants
# ---------------------------------------------------------------------------

_IA_L2_3_5_3 = dict(
    cmmc_practice_id="IA.L2-3.5.3",
    nist_control_id="3.5.3",
    control_family="Identification & Authentication (IA)",
    control_title="Multi-Factor Authentication for Local and Network Access",
)

_CM_L2_3_4_1 = dict(
    cmmc_practice_id="CM.L2-3.4.1",
    nist_control_id="3.4.1",
    control_family="Configuration Management (CM)",
    control_title="Baseline Configuration & Change Control",
)


# ---------------------------------------------------------------------------
# IA.L2-3.5.3 — MFA Evaluation
# ---------------------------------------------------------------------------


def _classify_mfa_users(
    users: Sequence[IamUserMfaRecord],
) -> tuple[list[IamUserMfaRecord], list[IamUserMfaRecord]]:
    """Partition users into compliant and non-compliant buckets."""
    compliant = [u for u in users if not u.is_at_risk]
    non_compliant = [u for u in users if u.is_at_risk]
    return compliant, non_compliant


def evaluate_iam_mfa(result: CredentialReportResult) -> Finding:
    """
    Evaluate IA.L2-3.5.3: require MFA for every IAM user that has console
    access (i.e. a password is enabled).

    A user is considered "at risk" when:
      - password_enabled is True  (they can authenticate to the AWS Console)
      - mfa_active is False       (they have no MFA device registered)

    Args:
        result: The output of collectors.aws.collect_iam_mfa_status().

    Returns:
        A Finding with PASS, FAIL, or ERROR status.
    """
    resource_scope = f"AWS Account {result.account_id}"
    base_kwargs = {**_IA_L2_3_5_3, "resource_scope": resource_scope}

    # ── Collection error short-circuit ──────────────────────────────────────
    if result.collection_errors:
        error_detail = "; ".join(result.collection_errors)
        logger.error("MFA evaluation aborted due to collection errors: %s", error_detail)
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.ERROR,
            summary=(
                "Evaluation could not complete due to AWS API collection errors."
            ),
            evidence=[f"Collection error: {e}" for e in result.collection_errors],
        )

    # ── No users found ───────────────────────────────────────────────────────
    if not result.users:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.PASS,
            summary="No IAM users with console access found; control is satisfied.",
            evidence=["IAM credential report returned zero user records (excluding root)."],
        )

    compliant_users, non_compliant_users = _classify_mfa_users(result.users)

    # Build evidence list — every user's status is logged for the auditor.
    evidence: list[str] = [
        f"Credential report generated at: {result.report_generated_at}",
        f"Total IAM users evaluated (excluding root): {len(result.users)}",
        f"Users with MFA ENABLED: {len(compliant_users)}",
        f"Users with MFA DISABLED (console access active): {len(non_compliant_users)}",
    ]

    for user in compliant_users:
        evidence.append(f"  [PASS] {user.username} — MFA active: {user.mfa_active}")

    for user in non_compliant_users:
        evidence.append(
            f"  [FAIL] {user.username} (ARN: {user.arn}) "
            f"— MFA active: {user.mfa_active}, "
            f"Console access: {user.has_console_access}"
        )

    if non_compliant_users:
        remediation = [
            f"Enable MFA for IAM user '{u.username}' "
            f"(navigate to IAM → Users → {u.username} → Security credentials → "
            f"Assign MFA device)."
            for u in non_compliant_users
        ]
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.FAIL,
            summary=(
                f"{len(non_compliant_users)} of {len(result.users)} IAM user(s) "
                f"have console access without MFA — CMMC IA.L2-3.5.3 is NOT satisfied."
            ),
            evidence=evidence,
            remediation_items=remediation,
        )

    return Finding(
        **base_kwargs,
        status=ComplianceStatus.PASS,
        summary=(
            f"All {len(compliant_users)} IAM user(s) with console access "
            f"have MFA enabled — CMMC IA.L2-3.5.3 is satisfied."
        ),
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# CM.L2-3.4.1 — Branch Protection Evaluation
# ---------------------------------------------------------------------------


def evaluate_branch_protection(result: BranchProtectionResult) -> Finding:
    """
    Evaluate CM.L2-3.4.1: verify that the repository's primary branch
    enforces pull-request reviews before code can be merged, establishing a
    baseline configuration change-control mechanism.

    A repository is considered compliant when:
      - Branch protection is enabled on the default/target branch.
      - At least one approving review is required before merge.

    Args:
        result: The output of collectors.github.collect_branch_protection().

    Returns:
        A Finding with PASS, FAIL, or ERROR status.
    """
    resource_scope = f"GitHub Repository: {result.repo_full_name}"
    base_kwargs = {**_CM_L2_3_4_1, "resource_scope": resource_scope}

    # ── Collection error short-circuit ──────────────────────────────────────
    if result.collection_errors:
        error_detail = "; ".join(result.collection_errors)
        logger.error(
            "Branch-protection evaluation aborted: %s", error_detail
        )
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.ERROR,
            summary=(
                "Evaluation could not complete due to GitHub API collection errors."
            ),
            evidence=[f"Collection error: {e}" for e in result.collection_errors],
        )

    details = result.details
    if details is None:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.ERROR,
            summary="No branch protection data was returned by the collector.",
            evidence=["BranchProtectionResult.details was None despite no errors."],
        )

    # Build a comprehensive evidence trail.
    evidence: list[str] = [
        f"Repository: {details.repo_full_name}",
        f"Branch inspected: {details.branch_name}",
        f"Default branch: {result.default_branch}",
        f"Branch protection enabled: {details.protection_enabled}",
        f"PR reviews required: {details.required_pr_reviews}",
        f"Required approving review count: {details.required_approving_review_count}",
        f"Dismiss stale reviews on push: {details.dismiss_stale_reviews}",
        f"Require code owner review: {details.require_code_owner_reviews}",
        f"Status checks required before merge: {details.require_status_checks}",
        f"Enforce rules on administrators: {details.enforce_admins}",
        f"Force-pushes allowed: {details.allow_force_pushes}",
        f"Branch deletions allowed: {details.allow_deletions}",
    ]

    # ── Primary compliance gate: protection must be on ───────────────────────
    if not details.protection_enabled:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.FAIL,
            summary=(
                f"Branch '{details.branch_name}' has NO protection rules — "
                f"direct pushes and force-pushes are unrestricted. "
                f"CMMC CM.L2-3.4.1 is NOT satisfied."
            ),
            evidence=evidence,
            remediation_items=[
                f"Enable Branch Protection on '{details.branch_name}' in "
                f"'{details.repo_full_name}': Settings → Branches → "
                f"Add branch protection rule.",
                "Require at least 1 approving pull request review before merging.",
                "Enable 'Dismiss stale pull request approvals when new commits are pushed'.",
                "Consider enabling 'Require review from Code Owners'.",
            ],
        )

    # ── Secondary gate: PR reviews must be required ──────────────────────────
    if not details.required_pr_reviews:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.FAIL,
            summary=(
                f"Branch '{details.branch_name}' has protection enabled but does NOT "
                f"require pull-request reviews — direct merges are unrestricted. "
                f"CMMC CM.L2-3.4.1 is NOT satisfied."
            ),
            evidence=evidence,
            remediation_items=[
                f"In '{details.repo_full_name}' branch protection rule for "
                f"'{details.branch_name}': enable "
                f"'Require a pull request before merging' with at least 1 "
                f"required approving review.",
            ],
        )

    # ── PASS ─────────────────────────────────────────────────────────────────
    return Finding(
        **base_kwargs,
        status=ComplianceStatus.PASS,
        summary=(
            f"Branch '{details.branch_name}' requires {details.required_approving_review_count} "
            f"approving PR review(s) before merge — CMMC CM.L2-3.4.1 is satisfied."
        ),
        evidence=evidence,
    )
