"""IAM checks from CIS AWS Foundations Benchmark v3.0.0, Section 1.

Control numbers are the v3.0.0 numbers. A later benchmark version
renumbers this section, so do not reuse these ids without checking.

Not implemented, on purpose:

* Password composition rules and a maximum password age. Older
  benchmarks had them. v3.0.0 dropped them, following NIST 800-63B.
* 1.6 hardware MFA for root, 1.7 root usage monitoring, 1.11 access
  keys at user creation, 1.13 one active key per user, and 1.14 key
  rotation every 90 days. Those are real v3.0.0 controls. 1.14 is not
  the same as 1.12: 1.12 is about keys sitting unused, 1.14 is about
  rotating keys on a schedule even while they are used.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar

from boto3.session import Session
from botocore.exceptions import ClientError

from cis_aws_scanner.check import Check
from cis_aws_scanner.models import Finding, Severity, Status
from cis_aws_scanner.registry import registry

MIN_PASSWORD_LENGTH: int = 14
MIN_PASSWORD_REUSE: int = 24
UNUSED_KEY_DAYS: int = 45


def _as_utc(value: datetime) -> datetime:
    """Return ``value`` as a timezone-aware UTC datetime."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))


def _load_password_policy(client: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Return ``(policy, error_message)``.

    Both values are None when the account has no custom password policy.
    That is IAM's ``NoSuchEntity`` error, and it means the control fails.
    Any other ``ClientError`` is returned as the error message.
    """
    try:
        policy = client.get_account_password_policy()["PasswordPolicy"]
    except ClientError as exc:
        if _error_code(exc) == "NoSuchEntity":
            return None, None
        return None, str(exc)
    return policy, None


@registry.register
class RootAccessKeyCheck(Check):
    """CIS 1.4: the root account must not have access keys."""

    id = "1.4"
    title = "No access keys for the root account"
    cis_reference = "1.4"
    severity = Severity.CRITICAL
    service = "iam"
    remediation = "Delete any root account access keys. Use IAM users or roles instead."

    def run(self, session: Session) -> list[Finding]:
        try:
            summary = session.client("iam").get_account_summary()["SummaryMap"]
        except ClientError as exc:
            return [self.finding(Status.ERROR, resource="root", error=str(exc))]
        keys_present = int(summary.get("AccountAccessKeysPresent", 0))
        status = Status.PASS if keys_present == 0 else Status.FAIL
        return [
            self.finding(
                status,
                resource="root",
                evidence=f"AccountAccessKeysPresent={keys_present}",
            )
        ]


@registry.register
class RootMfaCheck(Check):
    """CIS 1.5: the root account must have MFA enabled."""

    id = "1.5"
    title = "Root account has MFA enabled"
    cis_reference = "1.5"
    severity = Severity.CRITICAL
    service = "iam"
    remediation = "Enable a virtual or hardware MFA device on the root account."

    def run(self, session: Session) -> list[Finding]:
        try:
            summary = session.client("iam").get_account_summary()["SummaryMap"]
        except ClientError as exc:
            return [self.finding(Status.ERROR, resource="root", error=str(exc))]
        mfa_enabled = int(summary.get("AccountMFAEnabled", 0))
        status = Status.PASS if mfa_enabled == 1 else Status.FAIL
        return [
            self.finding(
                status,
                resource="root",
                evidence=f"AccountMFAEnabled={mfa_enabled}",
            )
        ]


@registry.register
class PasswordLengthCheck(Check):
    """CIS 1.8: the password policy minimum length is at least 14."""

    id = "1.8"
    title = "Password policy requires a minimum length of 14 characters"
    cis_reference = "1.8"
    severity = Severity.MEDIUM
    service = "iam"
    remediation = f"Set minimum password length to at least {MIN_PASSWORD_LENGTH}."

    def run(self, session: Session) -> list[Finding]:
        policy, error = _load_password_policy(session.client("iam"))
        if error is not None:
            return [self.finding(Status.ERROR, error=error)]
        if policy is None:
            return [self.finding(Status.FAIL, evidence="no password policy configured")]
        length = int(policy.get("MinimumPasswordLength", 0))
        status = Status.PASS if length >= MIN_PASSWORD_LENGTH else Status.FAIL
        return [self.finding(status, evidence=f"MinimumPasswordLength={length}")]


@registry.register
class PasswordReuseCheck(Check):
    """CIS 1.9: the password policy remembers at least 24 passwords."""

    id = "1.9"
    title = "Password policy prevents reuse of the last 24 passwords"
    cis_reference = "1.9"
    severity = Severity.MEDIUM
    service = "iam"
    remediation = f"Set password reuse prevention to {MIN_PASSWORD_REUSE} or more."

    def run(self, session: Session) -> list[Finding]:
        policy, error = _load_password_policy(session.client("iam"))
        if error is not None:
            return [self.finding(Status.ERROR, error=error)]
        if policy is None:
            return [self.finding(Status.FAIL, evidence="no password policy configured")]
        reuse = int(policy.get("PasswordReusePrevention", 0))
        status = Status.PASS if reuse >= MIN_PASSWORD_REUSE else Status.FAIL
        return [self.finding(status, evidence=f"PasswordReusePrevention={reuse}")]


@registry.register
class ConsoleMfaCheck(Check):
    """CIS 1.10: every IAM user with a console password has MFA.

    A user with no login profile passes, because MFA is not applicable.
    One finding is returned per user. An account with no users returns
    an empty list.
    """

    id = "1.10"
    title = "MFA is enabled for IAM users with console access"
    cis_reference = "1.10"
    severity = Severity.HIGH
    service = "iam"
    remediation = "Attach an MFA device to every IAM user with console access."

    def run(self, session: Session) -> list[Finding]:
        client = session.client("iam")
        try:
            user_names = _list_user_names(client)
        except ClientError as exc:
            return [self.finding(Status.ERROR, error=str(exc))]

        findings: list[Finding] = []
        for user_name in user_names:
            findings.append(self._evaluate_user(client, user_name))
        return findings

    def _evaluate_user(self, client: Any, user_name: str) -> Finding:
        remediation = f"Attach an MFA device to '{user_name}' or remove console access."
        try:
            client.get_login_profile(UserName=user_name)
        except ClientError as exc:
            if _error_code(exc) == "NoSuchEntity":
                return self.finding(
                    Status.PASS,
                    resource=user_name,
                    evidence="no login profile",
                    remediation=remediation,
                )
            return self.finding(
                Status.ERROR,
                resource=user_name,
                error=str(exc),
                remediation=remediation,
            )

        try:
            devices = client.list_mfa_devices(UserName=user_name)["MFADevices"]
        except ClientError as exc:
            return self.finding(
                Status.ERROR,
                resource=user_name,
                error=str(exc),
                remediation=remediation,
            )
        status = Status.PASS if len(devices) > 0 else Status.FAIL
        return self.finding(
            status,
            resource=user_name,
            evidence=f"mfa_device_count={len(devices)}",
            remediation=remediation,
        )


@registry.register
class AccessKeyAgeCheck(Check):
    """CIS 1.12: disable credentials unused for 45 days or more.

    Only Active keys are evaluated. An Inactive key is already disabled,
    so it is skipped and produces no finding.

    A key that has never been used is judged by its age (``CreateDate``),
    not failed automatically. A key created a few minutes ago has not had
    a chance to be used yet. The 45th day fails: CIS says 45 days or greater.
    """

    id = "1.12"
    title = "Active access keys are used within 45 days"
    cis_reference = "1.12"
    severity = Severity.MEDIUM
    service = "iam"
    remediation = "Deactivate or rotate access keys unused for 45 days or more."
    max_unused_days: ClassVar[int] = UNUSED_KEY_DAYS

    def run(self, session: Session) -> list[Finding]:
        client = session.client("iam")
        try:
            user_names = _list_user_names(client)
        except ClientError as exc:
            return [self.finding(Status.ERROR, error=str(exc))]

        findings: list[Finding] = []
        now = datetime.now(UTC)
        for user_name in user_names:
            try:
                findings.extend(self._evaluate_user(client, user_name, now))
            except ClientError as exc:
                findings.append(self.finding(Status.ERROR, resource=user_name, error=str(exc)))
        return findings

    def _evaluate_user(self, client: Any, user_name: str, now: datetime) -> list[Finding]:
        keys = client.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
        findings: list[Finding] = []
        for key in keys:
            if key.get("Status") != "Active":
                continue
            key_id = str(key["AccessKeyId"])
            last_used_response = client.get_access_key_last_used(AccessKeyId=key_id)
            last_used = last_used_response.get("AccessKeyLastUsed", {}).get("LastUsedDate")
            status, evidence = self._judge_key(key, last_used, now)
            findings.append(
                self.finding(
                    status,
                    resource=f"{user_name}/{key_id}",
                    evidence=evidence,
                    remediation=f"Rotate or deactivate access key {key_id} for '{user_name}'.",
                )
            )
        return findings

    def _judge_key(
        self,
        key: dict[str, Any],
        last_used: datetime | None,
        now: datetime,
    ) -> tuple[Status, str]:
        if last_used is None:
            age_days = (now - _as_utc(key["CreateDate"])).days
            status = Status.PASS if age_days < self.max_unused_days else Status.FAIL
            return status, f"never used; created {age_days} day(s) ago"
        age_days = (now - _as_utc(last_used)).days
        status = Status.PASS if age_days < self.max_unused_days else Status.FAIL
        return status, f"last used {age_days} day(s) ago"


def _list_user_names(client: Any) -> list[str]:
    names: list[str] = []
    for page in client.get_paginator("list_users").paginate():
        for user in page.get("Users", []):
            names.append(str(user["UserName"]))
    return names
