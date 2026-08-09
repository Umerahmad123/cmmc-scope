"""
AWS Collector — cmmc_scope/collectors/aws.py

Responsible for all interactions with the AWS API via boto3.
This module is intentionally side-effect-free: it fetches data and
returns it as plain Python structures. All compliance logic lives in engine.py.

CMMC Controls targeted:
  - IA.L2-3.5.3 (Multi-Factor Authentication)
  - AC.L2-3.1.1 (Account Access Control / Stale Accounts)
  - AU.L2-3.3.1 (Audit Logging / CloudTrail)
NIST SP 800-171 References: 3.5.3, 3.1.1, 3.3.1
"""

from __future__ import annotations

import csv
import io
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Transfer Objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IamUserMfaRecord:
    """Immutable record describing a single IAM user's MFA and login status."""

    username: str
    arn: str
    password_enabled: bool
    mfa_active: bool
    has_console_access: bool
    password_last_used: str
    days_since_login: int

    @property
    def is_at_risk(self) -> bool:
        return self.has_console_access and not self.mfa_active

    @property
    def is_stale(self) -> bool:
        if not self.has_console_access:
            return False
        if self.days_since_login == -1:
            return True
        return self.days_since_login >= 90


@dataclass
class CredentialReportResult:
    """Container for the full credential-report collection run."""

    account_id: str
    report_generated_at: str
    users: list[IamUserMfaRecord] = field(default_factory=list)
    collection_errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CloudTrailRecord:
    """Immutable record describing a single CloudTrail trail."""

    name: str
    home_region: str
    is_multi_region: bool
    is_logging: bool
    has_log_validation: bool
    s3_bucket: str


@dataclass
class CloudTrailResult:
    """Container for the CloudTrail collection run."""

    account_id: str
    region_checked: str
    trails: list[CloudTrailRecord] = field(default_factory=list)
    collection_errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers — IAM
# ---------------------------------------------------------------------------

_BOOL_TRUE_VALUES = {"true", "TRUE", "True"}
_MAX_REPORT_WAIT_SECONDS = 60
_REPORT_POLL_INTERVAL_SECONDS = 2
_STALE_THRESHOLD_DAYS = 90


def _str_to_bool(value: str) -> bool:
    return value in _BOOL_TRUE_VALUES


def _days_since(date_str: str) -> int:
    if not date_str or date_str in ("N/A", "no_information", "not_supported"):
        return -1
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return (now - dt).days
    except (ValueError, TypeError):
        return -1


def _wait_for_credential_report(iam_client: Any) -> None:
    logger.debug("Requesting IAM credential report generation...")
    deadline = time.monotonic() + _MAX_REPORT_WAIT_SECONDS

    while time.monotonic() < deadline:
        response = iam_client.generate_credential_report()
        state = response.get("State", "")
        logger.debug("Credential report state: %s", state)
        if state == "COMPLETE":
            return
        time.sleep(_REPORT_POLL_INTERVAL_SECONDS)

    raise RuntimeError(
        f"IAM credential report did not become ready within "
        f"{_MAX_REPORT_WAIT_SECONDS} seconds."
    )


def _parse_credential_report_csv(raw_csv: str) -> list[IamUserMfaRecord]:
    records: list[IamUserMfaRecord] = []
    reader = csv.DictReader(io.StringIO(raw_csv))

    for row in reader:
        username: str = row.get("user", "")
        if username == "<root_account>":
            continue

        password_enabled = _str_to_bool(row.get("password_enabled", "false"))
        mfa_active = _str_to_bool(row.get("mfa_active", "false"))
        password_last_used = row.get("password_last_used", "N/A")
        days_since_login = _days_since(password_last_used)

        records.append(
            IamUserMfaRecord(
                username=username,
                arn=row.get("arn", ""),
                password_enabled=password_enabled,
                mfa_active=mfa_active,
                has_console_access=password_enabled,
                password_last_used=password_last_used,
                days_since_login=days_since_login,
            )
        )

    logger.debug("Parsed %d IAM user records.", len(records))
    return records


# ---------------------------------------------------------------------------
# Public API — IAM
# ---------------------------------------------------------------------------


def collect_iam_mfa_status(
    profile_name: str | None = None,
    region_name: str = "us-east-1",
) -> CredentialReportResult:
    """
    Collect IAM MFA status and last-login data for all users.
    Used by both IA.L2-3.5.3 and AC.L2-3.1.1 evaluations.
    """
    result = CredentialReportResult(
        account_id="unknown",
        report_generated_at="unknown",
    )

    try:
        session = boto3.Session(profile_name=profile_name, region_name=region_name)
        iam_client = session.client("iam")
        sts_client = session.client("sts")

        caller_identity = sts_client.get_caller_identity()
        result.account_id = caller_identity.get("Account", "unknown")
        logger.info("Targeting AWS account: %s", result.account_id)

        _wait_for_credential_report(iam_client)

        report_response = iam_client.get_credential_report()
        content = report_response["Content"]
        raw_csv: str = (
            content.read().decode("utf-8")
            if hasattr(content, "read")
            else content.decode("utf-8")
        )
        result.report_generated_at = str(
            report_response.get("GeneratedTime", "unknown")
        )
        result.users = _parse_credential_report_csv(raw_csv)

    except ClientError as exc:
        msg = f"AWS ClientError [{exc.response['Error']['Code']}]: {exc.response['Error']['Message']}"
        logger.error(msg)
        result.collection_errors.append(msg)

    except BotoCoreError as exc:
        msg = f"BotoCoreError during AWS collection: {exc}"
        logger.error(msg)
        result.collection_errors.append(msg)

    except Exception as exc:
        msg = f"Unexpected error during AWS collection: {exc}"
        logger.exception(msg)
        result.collection_errors.append(msg)

    return result


# ---------------------------------------------------------------------------
# Public API — CloudTrail
# ---------------------------------------------------------------------------


def collect_cloudtrail_status(
    profile_name: str | None = None,
    region_name: str = "us-east-1",
) -> CloudTrailResult:
    """
    Collect CloudTrail trail configuration for the target AWS account.

    Checks whether CloudTrail is enabled, multi-region, actively logging,
    and has log file validation turned on.

    Used by AU.L2-3.3.1 evaluation.
    """
    result = CloudTrailResult(account_id="unknown", region_checked=region_name)

    try:
        session = boto3.Session(profile_name=profile_name, region_name=region_name)
        ct_client = session.client("cloudtrail")
        sts_client = session.client("sts")

        caller_identity = sts_client.get_caller_identity()
        result.account_id = caller_identity.get("Account", "unknown")
        logger.info("Collecting CloudTrail status for account: %s", result.account_id)

        # describe_trails returns all trails visible from this region.
        # includeShadowTrails=False returns only trails with home region = this region.
        # We use True to see all trails including multi-region ones homed elsewhere.
        trails_response = ct_client.describe_trails(includeShadowTrails=False)
        trail_list = trails_response.get("trailList", [])

        logger.debug("Found %d CloudTrail trail(s).", len(trail_list))

        for trail in trail_list:
            trail_name = trail.get("Name", "unknown")
            trail_arn = trail.get("TrailARN", "")

            # Get live logging status for this trail
            try:
                status_response = ct_client.get_trail_status(Name=trail_arn)
                is_logging = status_response.get("IsLogging", False)
            except ClientError:
                is_logging = False

            result.trails.append(
                CloudTrailRecord(
                    name=trail_name,
                    home_region=trail.get("HomeRegion", region_name),
                    is_multi_region=trail.get("IsMultiRegionTrail", False),
                    is_logging=is_logging,
                    has_log_validation=trail.get("LogFileValidationEnabled", False),
                    s3_bucket=trail.get("S3BucketName", "unknown"),
                )
            )

    except ClientError as exc:
        msg = f"AWS ClientError [{exc.response['Error']['Code']}]: {exc.response['Error']['Message']}"
        logger.error(msg)
        result.collection_errors.append(msg)

    except BotoCoreError as exc:
        msg = f"BotoCoreError during CloudTrail collection: {exc}"
        logger.error(msg)
        result.collection_errors.append(msg)

    except Exception as exc:
        msg = f"Unexpected error during CloudTrail collection: {exc}"
        logger.exception(msg)
        result.collection_errors.append(msg)

    return result