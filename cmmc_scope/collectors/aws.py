"""
AWS Collector — cmmc_scope/collectors/aws.py

Responsible for all interactions with the AWS API via boto3.
This module is intentionally side-effect-free: it fetches data and
returns it as plain Python structures. All compliance logic lives in engine.py.

CMMC Control targeted: IA.L2-3.5.3 (Multi-Factor Authentication)
NIST SP 800-171 Reference: 3.5.3
"""

from __future__ import annotations

import csv
import io
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Transfer Objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IamUserMfaRecord:
    """Immutable record describing a single IAM user's MFA status."""

    username: str
    arn: str
    password_enabled: bool
    mfa_active: bool
    # Console access is only meaningful for users with a password set.
    has_console_access: bool

    @property
    def is_at_risk(self) -> bool:
        """True when the user can log in via the console but has no MFA."""
        return self.has_console_access and not self.mfa_active


@dataclass
class CredentialReportResult:
    """Container for the full credential-report collection run."""

    account_id: str
    report_generated_at: str
    users: list[IamUserMfaRecord] = field(default_factory=list)
    collection_errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_BOOL_TRUE_VALUES = {"true", "TRUE", "True"}
_MAX_REPORT_WAIT_SECONDS = 60
_REPORT_POLL_INTERVAL_SECONDS = 2


def _str_to_bool(value: str) -> bool:
    """Convert a CSV boolean string ('true'/'false') to a Python bool."""
    return value in _BOOL_TRUE_VALUES


def _wait_for_credential_report(iam_client: Any) -> None:
    """
    Trigger credential-report generation and block until AWS reports it
    is complete.  Raises RuntimeError if the report never becomes ready.
    """
    logger.debug("Requesting IAM credential report generation…")
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
    """
    Parse the raw CSV content of an IAM credential report into a list of
    IamUserMfaRecord objects, skipping the root account row.
    """
    records: list[IamUserMfaRecord] = []
    reader = csv.DictReader(io.StringIO(raw_csv))

    for row in reader:
        username: str = row.get("user", "")

        # The root account row is represented as '<root_account>' — skip it
        # because root MFA is evaluated differently (not via IAM users).
        if username == "<root_account>":
            logger.debug("Skipping root account row in credential report.")
            continue

        password_enabled = _str_to_bool(row.get("password_enabled", "false"))
        mfa_active = _str_to_bool(row.get("mfa_active", "false"))

        records.append(
            IamUserMfaRecord(
                username=username,
                arn=row.get("arn", ""),
                password_enabled=password_enabled,
                mfa_active=mfa_active,
                has_console_access=password_enabled,
            )
        )

    logger.debug("Parsed %d IAM user records from credential report.", len(records))
    return records


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def collect_iam_mfa_status(
    profile_name: str | None = None,
    region_name: str = "us-east-1",
) -> CredentialReportResult:
    """
    Collect IAM MFA status for all users in the target AWS account.

    Uses the IAM Credential Report, which is the authoritative AWS source
    for password and MFA status across all IAM users.

    Args:
        profile_name: Optional AWS CLI named profile.  When None, boto3 falls
                      back to its standard credential chain (env vars, instance
                      profile, ~/.aws/credentials, etc.).
        region_name:  AWS region used to create the boto3 session.  The IAM
                      service is global, but a region is required for the
                      session itself.

    Returns:
        A CredentialReportResult containing the parsed user records and any
        non-fatal errors encountered during collection.
    """
    result = CredentialReportResult(account_id="unknown", report_generated_at="unknown")

    try:
        session = boto3.Session(profile_name=profile_name, region_name=region_name)
        iam_client = session.client("iam")
        sts_client = session.client("sts")

        # Resolve the numeric AWS account ID for the evidence report.
        caller_identity = sts_client.get_caller_identity()
        result.account_id = caller_identity.get("Account", "unknown")
        logger.info("Targeting AWS account: %s", result.account_id)

        # Generate and wait for the credential report.
        _wait_for_credential_report(iam_client)

        # Retrieve the report content.
        report_response = iam_client.get_credential_report()
        raw_csv: str = report_response["Content"].read().decode("utf-8")
        result.report_generated_at = str(
            report_response.get("GeneratedTime", "unknown")
        )

        result.users = _parse_credential_report_csv(raw_csv)

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        error_msg = exc.response["Error"]["Message"]
        msg = f"AWS ClientError [{error_code}]: {error_msg}"
        logger.error(msg)
        result.collection_errors.append(msg)

    except BotoCoreError as exc:
        msg = f"BotoCoreError during AWS collection: {exc}"
        logger.error(msg)
        result.collection_errors.append(msg)

    except Exception as exc:  # noqa: BLE001
        msg = f"Unexpected error during AWS collection: {exc}"
        logger.exception(msg)
        result.collection_errors.append(msg)

    return result
