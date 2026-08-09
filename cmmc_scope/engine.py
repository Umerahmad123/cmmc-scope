"""
Evaluation Engine — cmmc_scope/engine.py
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Sequence

from cmmc_scope.collectors.aws import (
    CredentialReportResult,
    CloudTrailResult,
    IamUserMfaRecord,
)
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
# Control metadata
# ---------------------------------------------------------------------------

_IA_L2_3_5_3 = dict(
    cmmc_practice_id="IA.L2-3.5.3",
    nist_control_id="3.5.3",
    control_family="Identification & Authentication (IA)",
    control_title="Multi-Factor Authentication for Local and Network Access",
)

_AC_L2_3_1_1 = dict(
    cmmc_practice_id="AC.L2-3.1.1",
    nist_control_id="3.1.1",
    control_family="Access Control (AC)",
    control_title="Authorized Access Control / Stale Account Detection",
)

_CM_L2_3_4_1 = dict(
    cmmc_practice_id="CM.L2-3.4.1",
    nist_control_id="3.4.1",
    control_family="Configuration Management (CM)",
    control_title="Baseline Configuration & Change Control",
)

_AU_L2_3_3_1 = dict(
    cmmc_practice_id="AU.L2-3.3.1",
    nist_control_id="3.3.1",
    control_family="Audit & Accountability (AU)",
    control_title="System Audit Logging / CloudTrail Verification",
)


# ---------------------------------------------------------------------------
# IA.L2-3.5.3 - MFA Evaluation
# ---------------------------------------------------------------------------


def evaluate_iam_mfa(result: CredentialReportResult) -> Finding:
    """Evaluate IA.L2-3.5.3: require MFA for every IAM user with console access."""
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

    compliant_users = [u for u in result.users if not u.is_at_risk]
    non_compliant_users = [u for u in result.users if u.is_at_risk]

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
            f"- MFA active: {user.mfa_active}, Console access: {user.has_console_access}"
        )

    if non_compliant_users:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.FAIL,
            summary=(
                f"{len(non_compliant_users)} of {len(result.users)} IAM user(s) "
                f"have console access without MFA - CMMC IA.L2-3.5.3 is NOT satisfied."
            ),
            evidence=evidence,
            remediation_items=[
                f"Enable MFA for IAM user '{u.username}' "
                f"(IAM > Users > {u.username} > Security credentials > Assign MFA device)."
                for u in non_compliant_users
            ],
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
    """Evaluate AC.L2-3.1.1: detect IAM users inactive for 90+ days."""
    resource_scope = f"AWS Account {result.account_id}"
    base_kwargs = {**_AC_L2_3_1_1, "resource_scope": resource_scope}

    if result.collection_errors:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.ERROR,
            summary="Evaluation could not complete due to AWS API collection errors.",
            evidence=[f"Collection error: {e}" for e in result.collection_errors],
        )

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
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.FAIL,
            summary=(
                f"{len(stale_users)} of {len(console_users)} IAM console user(s) "
                f"have not logged in for 90+ days - CMMC AC.L2-3.1.1 is NOT satisfied."
            ),
            evidence=evidence,
            remediation_items=[
                f"Disable or delete stale IAM user '{u.username}' "
                f"(last login: {u.password_last_used}). "
                f"If still needed, document the business justification."
                for u in stale_users
            ],
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
# AU.L2-3.3.1 - CloudTrail Audit Logging Evaluation
# ---------------------------------------------------------------------------


def evaluate_cloudtrail(result: CloudTrailResult) -> Finding:
    """
    Evaluate AU.L2-3.3.1: verify AWS CloudTrail is enabled, multi-region,
    actively logging, and has log file validation enabled.

    A compliant account must have at least one trail that is:
      - Multi-region (captures activity across all AWS regions)
      - Actively logging (IsLogging = True)
      - Log file validation enabled (detects tampering)
    """
    resource_scope = f"AWS Account {result.account_id}"
    base_kwargs = {**_AU_L2_3_3_1, "resource_scope": resource_scope}

    if result.collection_errors:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.ERROR,
            summary="Evaluation could not complete due to AWS API collection errors.",
            evidence=[f"Collection error: {e}" for e in result.collection_errors],
        )

    evidence: list[str] = [
        f"AWS Account: {result.account_id}",
        f"Region checked: {result.region_checked}",
        f"Total CloudTrail trails found: {len(result.trails)}",
    ]

    # No trails at all - clear FAIL
    if not result.trails:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.FAIL,
            summary=(
                "No CloudTrail trails found in this account - "
                "audit logging is completely disabled. "
                "CMMC AU.L2-3.3.1 is NOT satisfied."
            ),
            evidence=evidence + ["No trails returned by describe_trails API."],
            remediation_items=[
                "Enable AWS CloudTrail: go to CloudTrail > Create trail.",
                "Enable 'Apply trail to all regions' (multi-region trail).",
                "Enable 'Log file validation' to detect tampering.",
                "Ensure the trail status shows 'Logging: On'.",
            ],
        )

    # Evaluate each trail
    compliant_trails = []
    issues_by_trail: dict[str, list[str]] = {}

    for trail in result.trails:
        trail_issues: list[str] = []

        if not trail.is_multi_region:
            trail_issues.append("not multi-region (misses activity in other regions)")
        if not trail.is_logging:
            trail_issues.append("logging is OFF (trail exists but not recording)")
        if not trail.has_log_validation:
            trail_issues.append("log file validation disabled (tampering undetectable)")

        evidence.append(
            f"  Trail: {trail.name} | Region: {trail.home_region} | "
            f"Multi-region: {trail.is_multi_region} | "
            f"Logging: {trail.is_logging} | "
            f"Log validation: {trail.has_log_validation} | "
            f"S3 bucket: {trail.s3_bucket}"
        )

        if trail_issues:
            issues_by_trail[trail.name] = trail_issues
        else:
            compliant_trails.append(trail)

    # At least one fully compliant trail = PASS
    if compliant_trails:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.PASS,
            summary=(
                f"{len(compliant_trails)} of {len(result.trails)} CloudTrail trail(s) "
                f"are multi-region, actively logging, and have validation enabled - "
                f"CMMC AU.L2-3.3.1 is satisfied."
            ),
            evidence=evidence,
        )

    # Trails exist but none are fully compliant
    remediation: list[str] = []
    for trail_name, trail_issues in issues_by_trail.items():
        for issue in trail_issues:
            remediation.append(f"Trail '{trail_name}': {issue}.")

    return Finding(
        **base_kwargs,
        status=ComplianceStatus.FAIL,
        summary=(
            f"{len(result.trails)} CloudTrail trail(s) found but none are fully compliant - "
            f"CMMC AU.L2-3.3.1 is NOT satisfied."
        ),
        evidence=evidence,
        remediation_items=remediation,
    )


# ---------------------------------------------------------------------------
# CM.L2-3.4.1 - Branch Protection Evaluation
# ---------------------------------------------------------------------------


def evaluate_branch_protection(result: BranchProtectionResult) -> Finding:
    """Evaluate CM.L2-3.4.1: verify branch protection requires PR reviews."""
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
                f"CMMC CM.L2-3.4.1 is NOT satisfied."
            ),
            evidence=evidence,
            remediation_items=[
                f"Enable Branch Protection on '{details.branch_name}': "
                f"Settings > Branches > Add branch protection rule.",
                "Require at least 1 approving pull request review before merging.",
            ],
        )

    if not details.required_pr_reviews:
        return Finding(
            **base_kwargs,
            status=ComplianceStatus.FAIL,
            summary=(
                f"Branch '{details.branch_name}' has protection but does NOT "
                f"require PR reviews - CMMC CM.L2-3.4.1 is NOT satisfied."
            ),
            evidence=evidence,
            remediation_items=[
                f"Enable 'Require a pull request before merging' with at least "
                f"1 required approving review on branch '{details.branch_name}'.",
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