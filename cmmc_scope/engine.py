"""
Evaluation Engine — cmmc_scope/engine.py

Applies deterministic pass/fail logic to produce structured Finding objects
mapped to official CMMC / NIST SP 800-171 control identifiers.

Design invariants:
  - No I/O occurs here.
  - All functions are pure: same inputs, same outputs.
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
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    NOT_APPLICABLE = "N/A"


@dataclass
class Finding:
    cmmc_practice_id: str
    nist_control_id: str
    control_family: str
    control_title: str
    status: ComplianceStatus
    summary: str
    evidence: list[str] = field(default_factory=list)
    remediation_items: list[str] = field(default_factory=list)
    evaluated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    resource_scope: str = ""


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

_AC_L2_3_1_1 = dict(
    cmmc_practice_id="AC.L2-3.1.1",
    nist_control_id="3.1.1",
    control_family="Access Control (AC)",
    control_title="Authorized Access Control / Stale Account Detection",
)


# ---------------------------------------------------------------------------
# IA.L2-3.5.3 - MFA Evaluation
# ---------------------------------------------------------------------------


def _classify_mfa_users(
    users: Sequence[IamUserMfaRecord],
) -> tuple[list[IamUserMfaRecord], list[IamUserMfaRecord]]:
    compliant = [u for u in users if not u.is_at_risk]
    non_compliant = [u for u in users if u.is_at_risk]
    return compliant, non_compliant


def evaluate_iam_mfa(result: CredentialReportResult) -> Finding:
    """
    Evaluate IA.L2-3.5.3: require MFA for every IAM user that has console
    access.
    """
    resource_scope = f"AWS Account {result.account_id}"
    base_kwargs = {**_IA_L2_3_5_3, "resource_scope": resource_scope}

    if result.collection_errors:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.ERROR,
            summary="Evaluation could not complete due to AWS API collection errors.",
            evidence=[f"Collection error: {e}" for e in result.collection_errors],
        )

    if not result.users:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.PASS,
            summary="No IAM users with console access found; control is satisfied.",
            evidence=["IAM credential report returned zero user records (excluding root)."],
        )

    compliant_users, non_compliant_users = _classify_mfa_users(result.users)

    evidence: list[str] = [
        f"Credential report generated at: {result.report_generated_at}",
        f"Total IAM users evaluated (excluding root): {len(result.users)}",
        f"Users with MFA ENABLED: {len(compliant_users)}",
        f"Users with MFA DISABLED (console access active): {len(non_compliant_users)}",
    ]

    for user in compliant_users:
        evidence.append(f"  [PASS] {user.username} - MFA active: {user.mfa_active}")

    for user in non_compliant_users:
        evidence.append(
            f"  [FAIL] {user.username} (ARN: {user.arn}) "
            f"- MFA active: {user.mfa_active}, "
            f"Console access: {user.has_console_access}"
        )

    if non_compliant_users:
        remediation = [
            f"Enable MFA for IAM user '{u.username}' "
            f"(IAM > Users > {u.username} > Security credentials > Assign MFA device)."
            for u in non_compliant_users
        ]
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.FAIL,
            summary=(
                f"{len(non_compliant_users)} of {len(result.users)} IAM user(s) "
                f"have console access without MFA - CMMC IA.L2-3.5.3 is NOT satisfied."
            ),
            evidence=evidence,
            remediation_items=remediation,
        )

    return Finding(
        **base_kwargs,
        status=ComplianceStatus.PASS,
        summary=(
            f"All {len(compliant_users)} IAM user(s) with console access "
            f"have MFA enabled - CMMC IA.L2-3.5.3 is satisfied."
        ),
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# AC.L2-3.1.1 - Stale Account Evaluation
# ---------------------------------------------------------------------------


def evaluate_stale_accounts(result: CredentialReportResult) -> Finding:
    """
    Evaluate AC.L2-3.1.1: detect IAM users with console access who have not
    logged in for 90 or more days, or have never logged in.

    Stale accounts that remain active violate the principle of least privilege
    and are a common finding in CMMC assessments.
    """
    resource_scope = f"AWS Account {result.account_id}"
    base_kwargs = {**_AC_L2_3_1_1, "resource_scope": resource_scope}

    if result.collection_errors:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.ERROR,
            summary="Evaluation could not complete due to AWS API collection errors.",
            evidence=[f"Collection error: {e}" for e in result.collection_errors],
        )

    # Only evaluate users who have console access
    console_users = [u for u in result.users if u.has_console_access]

    if not console_users:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.PASS,
            summary="No IAM users with console access found; control is satisfied.",
            evidence=["IAM credential report returned zero console users (excluding root)."],
        )

    stale_users = [u for u in console_users if u.is_stale]
    active_users = [u for u in console_users if not u.is_stale]

    evidence: list[str] = [
        f"Credential report generated at: {result.report_generated_at}",
        f"Total IAM console users evaluated: {len(console_users)}",
        f"Active users (logged in within 90 days): {len(active_users)}",
        f"Stale users (90+ days or never logged in): {len(stale_users)}",
        f"Stale account threshold: 90 days",
    ]

    for user in active_users:
        days = user.days_since_login
        days_str = f"{days} days ago" if days >= 0 else "never"
        evidence.append(
            f"  [PASS] {user.username} - Last login: {user.password_last_used} ({days_str})"
        )

    for user in stale_users:
        days = user.days_since_login
        days_str = f"{days} days ago" if days >= 0 else "NEVER"
        evidence.append(
            f"  [FAIL] {user.username} (ARN: {user.arn}) "
            f"- Last login: {user.password_last_used} ({days_str})"
        )

    if stale_users:
        remediation = [
            f"Disable or delete stale IAM user '{u.username}' "
            f"(last login: {u.password_last_used}). "
            f"If the account is still needed, ensure the user logs in to confirm "
            f"active use, then document the business justification."
            for u in stale_users
        ]
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.FAIL,
            summary=(
                f"{len(stale_users)} of {len(console_users)} IAM console user(s) "
                f"have not logged in for 90+ days or have never logged in - "
                f"CMMC AC.L2-3.1.1 is NOT satisfied."
            ),
            evidence=evidence,
            remediation_items=remediation,
        )

    return Finding(
        **base_kwargs,
        status=ComplianceStatus.PASS,
        summary=(
            f"All {len(active_users)} IAM console user(s) have logged in within "
            f"the last 90 days - CMMC AC.L2-3.1.1 is satisfied."
        ),
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# CM.L2-3.4.1 - Branch Protection Evaluation
# ---------------------------------------------------------------------------


def evaluate_branch_protection(result: BranchProtectionResult) -> Finding:
    """
    Evaluate CM.L2-3.4.1: verify that the repository's primary branch
    enforces pull-request reviews before code can be merged.
    """
    resource_scope = f"GitHub Repository: {result.repo_full_name}"
    base_kwargs = {**_CM_L2_3_4_1, "resource_scope": resource_scope}

    if result.collection_errors:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.ERROR,
            summary="Evaluation could not complete due to GitHub API collection errors.",
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

    if not details.protection_enabled:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.FAIL,
            summary=(
                f"Branch '{details.branch_name}' has NO protection rules - "
                f"direct pushes and force-pushes are unrestricted. "
                f"CMMC CM.L2-3.4.1 is NOT satisfied."
            ),
            evidence=evidence,
            remediation_items=[
                f"Enable Branch Protection on '{details.branch_name}' in "
                f"'{details.repo_full_name}': Settings > Branches > "
                f"Add branch protection rule.",
                "Require at least 1 approving pull request review before merging.",
                "Enable 'Dismiss stale pull request approvals when new commits are pushed'.",
            ],
        )

    if not details.required_pr_reviews:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.FAIL,
            summary=(
                f"Branch '{details.branch_name}' has protection enabled but does NOT "
                f"require pull-request reviews - direct merges are unrestricted. "
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

    return Finding(
        **base_kwargs,
        status=ComplianceStatus.PASS,
        summary=(
            f"Branch '{details.branch_name}' requires "
            f"{details.required_approving_review_count} approving PR review(s) "
            f"before merge - CMMC CM.L2-3.4.1 is satisfied."
        ),
        evidence=evidence,
    )