"""
checks/iam_checks.py

CIS AWS Foundations Benchmark v3.0.0 (2024-01-31) checks for IAM
(Section 1): root account hygiene, account password policy, and MFA /
access-key hygiene for IAM users.

Control IDs below are pinned to CIS AWS Foundations Benchmark v3.0.0
specifically (verified against the published benchmark's own numbering,
not a third party's remapping of it). If you target a different
benchmark version, re-check every ID before relying on it.

Deliberately NOT implemented here (present in v3.0.0 but out of scope
for this milestone): 1.6 hardware MFA for root, 1.7 root user usage
monitoring, 1.11 no access keys at initial user setup, 1.13 only one
active access key per user, 1.14 access keys rotated every 90 days.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Final

import boto3
from botocore.exceptions import ClientError

from cis_aws_scanner.models import CheckResult, CheckStatus

MINIMUM_PASSWORD_LENGTH: Final = 14
MINIMUM_PASSWORD_REUSE_PREVENTION: Final = 24
UNUSED_CREDENTIALS_THRESHOLD_DAYS: Final = 45


class IAMChecker(object):
    """
    Runs CIS AWS Foundations Benchmark v3.0.0 IAM checks against a
    single AWS account using boto3.

    Attributes:
        _client (Any): private. The boto3 IAM client used to query AWS.
    """

    def __init__(self, session: boto3.Session | None = None) -> None:
        """
        Non-default constructor. Initializes an IAMChecker instance.

        Parameters:
            session (boto3.Session | None): An existing boto3 session to
                reuse. If None, a new default session is created.
        """
        active_session: boto3.Session = session if session is not None else boto3.Session()
        self._client: Any = active_session.client("iam")

    @property
    def client(self) -> Any:
        """
        Get the underlying boto3 IAM client.
        """
        return self._client

    def check_root_mfa_enabled(self) -> CheckResult:
        """
        CIS 1.5: Ensure MFA is enabled for the 'root' user account.

        Returns:
            CheckResult: PASS if root MFA is enabled, FAIL otherwise,
                ERROR on API failure.
        """
        control_id: str = "1.5"
        description: str = "Root account has MFA enabled"
        remediation: str = "Enable a virtual or hardware MFA device on the root account."
        try:
            summary: dict[str, Any] = self._client.get_account_summary()
            mfa_enabled: int = summary["SummaryMap"].get("AccountMFAEnabled", 0)
            status: CheckStatus = CheckStatus.PASS if mfa_enabled == 1 else CheckStatus.FAIL
            return CheckResult(control_id, description, status, "root", remediation)
        except ClientError as exc:
            return CheckResult(
                control_id, description, CheckStatus.ERROR, "root", remediation, error=str(exc)
            )

    def check_no_root_access_keys(self) -> CheckResult:
        """
        CIS 1.4: Ensure no 'root' user account access key exists.

        Returns:
            CheckResult: PASS if no root access keys exist, FAIL
                otherwise, ERROR on API failure.
        """
        control_id: str = "1.4"
        description: str = "No active access keys for the root account"
        remediation: str = "Delete any root account access keys; use IAM users/roles instead."
        try:
            summary: dict[str, Any] = self._client.get_account_summary()
            keys_present: int = summary["SummaryMap"].get("AccountAccessKeysPresent", 0)
            status: CheckStatus = CheckStatus.PASS if keys_present == 0 else CheckStatus.FAIL
            return CheckResult(control_id, description, status, "root", remediation)
        except ClientError as exc:
            return CheckResult(
                control_id, description, CheckStatus.ERROR, "root", remediation, error=str(exc)
            )

    # CIS 1.8 and 1.9 are the only account-password-policy controls left in
    # v3.0.0. Earlier benchmark versions (e.g. v1.2.0) also checked symbol /
    # number / uppercase / lowercase composition and a 90-day max age; CIS
    # dropped those in later versions, in line with NIST 800-63B guidance
    # against mandatory composition rules and periodic rotation. They are
    # intentionally not reimplemented here so every control_id below maps to
    # a real v3.0.0 recommendation.
    _PASSWORD_POLICY_CONTROLS: Final = (
        ("1.8", "Password policy requires a minimum length of 14 characters"),
        ("1.9", "Password policy prevents reuse of the last 24 passwords"),
    )

    def check_password_policy(self) -> list[CheckResult]:
        """
        CIS 1.8-1.9: Ensure the account password policy meets minimum
        length and reuse-prevention rules.

        Returns:
            list[CheckResult]: One result per password policy sub-check.
        """
        try:
            policy: dict[str, Any] = self._client.get_account_password_policy()["PasswordPolicy"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                # No custom password policy has been configured at all,
                # which means every CIS sub-check below is unmet.
                return self._password_policy_results(status=CheckStatus.FAIL)
            return self._password_policy_error_results(str(exc))

        return [
            self._evaluate_min_length(policy),
            self._evaluate_reuse_prevention(policy),
        ]

    def _password_policy_results(self, status: CheckStatus) -> list[CheckResult]:
        """
        Build a uniform set of password policy sub-check results, all
        sharing the same status. Used when no custom password policy is
        configured at all, which means every sub-check is unmet.

        Parameters:
            status (CheckStatus): The status to apply to every sub-check.

        Returns:
            list[CheckResult]: One result per password policy sub-check.
        """
        remediation: str = "Configure an account password policy meeting CIS v3.0.0 minimums."
        return [
            CheckResult(control_id, description, status, "account", remediation)
            for control_id, description in self._PASSWORD_POLICY_CONTROLS
        ]

    def _password_policy_error_results(self, error_message: str) -> list[CheckResult]:
        """
        Parameters:
            error_message (str): The error raised while fetching the
                password policy.

        Returns:
            list[CheckResult]: One ERROR result per password policy
                sub-check, sharing the same error message.
        """
        remediation: str = "Configure an account password policy meeting CIS v3.0.0 minimums."
        return [
            CheckResult(control_id, description, CheckStatus.ERROR, "account", remediation, error=error_message)
            for control_id, description in self._PASSWORD_POLICY_CONTROLS
        ]

    def _evaluate_min_length(self, policy: dict[str, Any]) -> CheckResult:
        """
        Parameters:
            policy (dict[str, Any]): The account password policy from IAM.

        Returns:
            CheckResult: PASS if minimum length >= 14 characters.
        """
        length: int = policy.get("MinimumPasswordLength", 0)
        status: CheckStatus = CheckStatus.PASS if length >= MINIMUM_PASSWORD_LENGTH else CheckStatus.FAIL
        return CheckResult(
            "1.8",
            "Password policy requires a minimum length of 14 characters",
            status,
            "account",
            f"Set minimum password length to at least {MINIMUM_PASSWORD_LENGTH}.",
            evidence=f"MinimumPasswordLength={length}",
        )

    def _evaluate_reuse_prevention(self, policy: dict[str, Any]) -> CheckResult:
        """
        Parameters:
            policy (dict[str, Any]): The account password policy from IAM.

        Returns:
            CheckResult: PASS if the policy blocks reuse of the last 24
                passwords.
        """
        reuse_prevention: int = policy.get("PasswordReusePrevention", 0)
        status: CheckStatus = (
            CheckStatus.PASS
            if reuse_prevention >= MINIMUM_PASSWORD_REUSE_PREVENTION
            else CheckStatus.FAIL
        )
        return CheckResult(
            "1.9",
            "Password policy prevents reuse of the last 24 passwords",
            status,
            "account",
            f"Set password reuse prevention to {MINIMUM_PASSWORD_REUSE_PREVENTION} or more.",
            evidence=f"PasswordReusePrevention={reuse_prevention}",
        )

    def check_mfa_for_console_users(self) -> list[CheckResult]:
        """
        CIS 1.10: Ensure MFA is enabled for all IAM users that have a
        console password.

        Returns:
            list[CheckResult]: One result per IAM user in the account.
        """
        control_id: str = "1.10"
        results: list[CheckResult] = []
        try:
            paginator = self._client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    results.append(self._evaluate_user_mfa(user["UserName"]))
        except ClientError as exc:
            results.append(
                CheckResult(
                    control_id,
                    "MFA enabled for console users",
                    CheckStatus.ERROR,
                    "account",
                    "Attach an MFA device to every IAM user with console access.",
                    error=str(exc),
                )
            )
        return results

    def _evaluate_user_mfa(self, user_name: str) -> CheckResult:
        """
        Parameters:
            user_name (str): The IAM user to evaluate.

        Returns:
            CheckResult: PASS if the user has no console password, or has
                one and at least one MFA device attached. FAIL if a
                console password exists with no MFA device attached.
        """
        control_id: str = "1.10"
        description: str = f"IAM user '{user_name}' has MFA enabled if console access is enabled"
        remediation: str = f"Attach an MFA device to '{user_name}' or remove console access."

        has_console_access: bool
        try:
            self._client.get_login_profile(UserName=user_name)
            has_console_access = True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                has_console_access = False
            else:
                return CheckResult(
                    control_id, description, CheckStatus.ERROR, user_name, remediation, error=str(exc)
                )

        if not has_console_access:
            return CheckResult(
                control_id, description, CheckStatus.PASS, user_name, remediation, evidence="no login profile"
            )

        mfa_devices: list[Any] = self._client.list_mfa_devices(UserName=user_name)["MFADevices"]
        status: CheckStatus = CheckStatus.PASS if len(mfa_devices) > 0 else CheckStatus.FAIL
        return CheckResult(
            control_id,
            description,
            status,
            user_name,
            remediation,
            evidence=f"mfa_device_count={len(mfa_devices)}",
        )

    def check_unused_access_keys(
        self, max_unused_days: int = UNUSED_CREDENTIALS_THRESHOLD_DAYS
    ) -> list[CheckResult]:
        """
        CIS 1.12: Ensure credentials unused for 45 days or greater are
        disabled.

        Only evaluates Active access keys — a key already marked
        Inactive isn't a finding, so it's skipped rather than flagged.
        A key that has never been used is judged by its age (CreateDate),
        not flagged automatically: a key created ten minutes ago simply
        hasn't had a chance to be used yet.

        Parameters:
            max_unused_days (int): Threshold, in days, past which an
                unused (or never-used) active access key is considered a
                finding. Defaults to 45, per CIS 1.12.

        Returns:
            list[CheckResult]: One result per Active access key found
                across all IAM users. Inactive keys produce no result.
        """
        results: list[CheckResult] = []
        control_id: str = "1.12"
        try:
            paginator = self._client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    results.extend(self._evaluate_user_access_keys(user["UserName"], max_unused_days))
        except ClientError as exc:
            results.append(
                CheckResult(
                    control_id,
                    "Access key usage check",
                    CheckStatus.ERROR,
                    "account",
                    f"Disable access keys unused for {max_unused_days}+ days.",
                    error=str(exc),
                )
            )
        return results

    def _evaluate_user_access_keys(self, user_name: str, max_unused_days: int) -> list[CheckResult]:
        """
        Parameters:
            user_name (str): The IAM user whose access keys to evaluate.
            max_unused_days (int): Threshold, in days, past which an
                unused (or never-used) active access key is considered a
                finding.

        Returns:
            list[CheckResult]: One result per Active access key
                belonging to this user. Inactive keys are skipped
                entirely (no result is produced for them).
        """
        control_id: str = "1.12"
        results: list[CheckResult] = []
        keys: list[Any] = self._client.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
        now: datetime = datetime.now(timezone.utc)

        for key in keys:
            if key.get("Status") != "Active":
                # An already-disabled key isn't a finding for this check.
                continue

            key_id: str = key["AccessKeyId"]
            description: str = (
                f"Access key {key_id} for '{user_name}' used within {max_unused_days} days"
            )
            remediation: str = f"Rotate or deactivate access key {key_id} for '{user_name}'."

            last_used: dict[str, Any] = self._client.get_access_key_last_used(AccessKeyId=key_id).get(
                "AccessKeyLastUsed", {}
            )
            last_used_date: datetime | None = last_used.get("LastUsedDate")

            status: CheckStatus
            evidence: str
            if last_used_date is None:
                # Never used: judge by how long the key has existed, not
                # an automatic FAIL. A brand-new key hasn't had time to
                # be used yet.
                create_date: datetime = key["CreateDate"]
                age_days: int = (now - create_date).days
                status = CheckStatus.PASS if age_days < max_unused_days else CheckStatus.FAIL
                evidence = f"never used; created {age_days} day(s) ago"
            else:
                age_days = (now - last_used_date).days
                status = CheckStatus.PASS if age_days < max_unused_days else CheckStatus.FAIL
                evidence = f"last used {age_days} day(s) ago"

            results.append(
                CheckResult(control_id, description, status, f"{user_name}/{key_id}", remediation, evidence=evidence)
            )
        return results

    def run_all(self) -> list[CheckResult]:
        """
        Run every IAM check and collect the results.

        Returns:
            list[CheckResult]: All IAM check results, in a stable order.
        """
        results: list[CheckResult] = []
        results.append(self.check_root_mfa_enabled())
        results.append(self.check_no_root_access_keys())
        results.extend(self.check_password_policy())
        results.extend(self.check_mfa_for_console_users())
        results.extend(self.check_unused_access_keys())
        return results

    def __str__(self) -> str:
        """
        Return a readable string representation of this checker.
        """
        return "IAMChecker(section='CIS 1 - Identity and Access Management', benchmark='v3.0.0')"
