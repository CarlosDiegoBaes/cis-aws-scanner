"""
tests/test_iam_checks.py

Unit tests for IAMChecker. Most tests use moto to mock AWS IAM so they
run without real AWS credentials, a real account, or network access.
The access-key age tests instead mock the boto3 client directly with
unittest.mock, since moto can't backdate CreateDate/LastUsedDate to
exact day boundaries.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from cis_aws_scanner.checks.iam_checks import IAMChecker, UNUSED_CREDENTIALS_THRESHOLD_DAYS
from cis_aws_scanner.models import CheckStatus


@mock_aws
def test_root_mfa_check_fails_by_default() -> None:
    """
    A freshly mocked account has no root MFA device, so the check
    should FAIL.
    """
    session: boto3.Session = boto3.Session(region_name="us-east-1")
    checker: IAMChecker = IAMChecker(session=session)

    result = checker.check_root_mfa_enabled()

    assert result.status == CheckStatus.FAIL
    assert result.control_id == "1.5"


def test_root_mfa_check_reports_error_separately_from_remediation() -> None:
    """
    An AWS API failure (e.g. AccessDenied) should produce an ERROR
    result whose `error` field holds the exception message, while
    `remediation` keeps its static fix-it text rather than being
    overwritten by the exception.
    """
    checker: IAMChecker = IAMChecker.__new__(IAMChecker)
    checker._client = MagicMock()
    checker._client.get_account_summary.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "not authorized"}},
        "GetAccountSummary",
    )

    result = checker.check_root_mfa_enabled()

    assert result.status == CheckStatus.ERROR
    assert "AccessDenied" in result.error
    assert "not authorized" in result.error
    assert result.remediation == "Enable a virtual or hardware MFA device on the root account."


@mock_aws
def test_no_root_access_keys_passes_by_default() -> None:
    """
    A freshly mocked account has no root access keys, so the check
    should PASS.
    """
    session: boto3.Session = boto3.Session(region_name="us-east-1")
    checker: IAMChecker = IAMChecker(session=session)

    result = checker.check_no_root_access_keys()

    assert result.status == CheckStatus.PASS
    assert result.control_id == "1.4"


@mock_aws
def test_password_policy_fails_when_not_set() -> None:
    """
    An account with no password policy configured should fail both
    CIS v3.0.0 password policy sub-checks (1.8, 1.9).
    """
    session: boto3.Session = boto3.Session(region_name="us-east-1")
    checker: IAMChecker = IAMChecker(session=session)

    results = checker.check_password_policy()

    assert len(results) == 2
    assert {result.control_id for result in results} == {"1.8", "1.9"}
    assert all(result.status == CheckStatus.FAIL for result in results)


@mock_aws
def test_password_policy_passes_when_compliant() -> None:
    """
    A password policy meeting the CIS v3.0.0 thresholds (min length 14,
    reuse prevention 24) should pass both sub-checks.
    """
    session: boto3.Session = boto3.Session(region_name="us-east-1")
    iam_client = session.client("iam")
    iam_client.update_account_password_policy(
        MinimumPasswordLength=14,
        PasswordReusePrevention=24,
    )
    checker: IAMChecker = IAMChecker(session=session)

    results = checker.check_password_policy()

    assert all(result.status == CheckStatus.PASS for result in results)


@mock_aws
def test_mfa_check_flags_user_with_console_access_and_no_mfa() -> None:
    """
    An IAM user with a login profile but no MFA device should FAIL.
    """
    session: boto3.Session = boto3.Session(region_name="us-east-1")
    iam_client = session.client("iam")
    iam_client.create_user(UserName="alice")
    iam_client.create_login_profile(UserName="alice", Password="Sup3r$ecret!")
    checker: IAMChecker = IAMChecker(session=session)

    results = checker.check_mfa_for_console_users()

    assert len(results) == 1
    assert results[0].status == CheckStatus.FAIL
    assert results[0].control_id == "1.10"
    assert results[0].resource == "alice"


@mock_aws
def test_mfa_check_passes_user_with_no_console_access() -> None:
    """
    An IAM user with no login profile (no console access) should PASS,
    since MFA is not applicable.
    """
    session: boto3.Session = boto3.Session(region_name="us-east-1")
    iam_client = session.client("iam")
    iam_client.create_user(UserName="service-account")
    checker: IAMChecker = IAMChecker(session=session)

    results = checker.check_mfa_for_console_users()

    assert len(results) == 1
    assert results[0].status == CheckStatus.PASS


@mock_aws
def test_run_all_returns_combined_results() -> None:
    """
    run_all() should combine every IAM sub-check into a single list.
    """
    session: boto3.Session = boto3.Session(region_name="us-east-1")
    checker: IAMChecker = IAMChecker(session=session)

    results = checker.run_all()

    # 1 (root MFA) + 1 (root keys) + 2 (password policy) = 4, plus zero
    # per-user checks since no IAM users exist in a fresh mocked account.
    assert len(results) == 4


# --- CIS 1.12 (unused access keys): edge cases -----------------------------
#
# These use a mocked client rather than moto, so CreateDate / LastUsedDate
# can be pinned to exact day boundaries around the 45-day CIS threshold.


def _checker_with_mocked_client() -> tuple[IAMChecker, MagicMock]:
    """
    Returns:
        tuple[IAMChecker, MagicMock]: An IAMChecker built without a real
            boto3 session, plus the MagicMock standing in for its IAM
            client, so tests can script exact API responses.
    """
    checker: IAMChecker = IAMChecker.__new__(IAMChecker)
    mock_client: MagicMock = MagicMock()
    checker._client = mock_client
    return checker, mock_client


def _access_key(key_id: str, status: str, create_date: datetime) -> dict:
    """
    Parameters:
        key_id (str): The access key ID.
        status (str): "Active" or "Inactive".
        create_date (datetime): When the key was created.

    Returns:
        dict: A single AccessKeyMetadata entry as list_access_keys
            would return it.
    """
    return {"AccessKeyId": key_id, "Status": status, "CreateDate": create_date}


def test_new_never_used_key_passes() -> None:
    """
    A key created moments ago that has never been used should PASS: it
    simply hasn't had time to be used yet, and shouldn't be judged the
    same as a stale key.
    """
    checker, mock_client = _checker_with_mocked_client()
    now: datetime = datetime.now(timezone.utc)
    mock_client.list_access_keys.return_value = {
        "AccessKeyMetadata": [_access_key("AKIA_NEW", "Active", now)]
    }
    mock_client.get_access_key_last_used.return_value = {"AccessKeyLastUsed": {}}

    results = checker._evaluate_user_access_keys("bob", UNUSED_CREDENTIALS_THRESHOLD_DAYS)

    assert len(results) == 1
    assert results[0].status == CheckStatus.PASS


def test_old_never_used_key_fails() -> None:
    """
    A key created 100 days ago that has never been used should FAIL:
    it's had ample time to be used and wasn't.
    """
    checker, mock_client = _checker_with_mocked_client()
    old_create_date: datetime = datetime.now(timezone.utc) - timedelta(days=100)
    mock_client.list_access_keys.return_value = {
        "AccessKeyMetadata": [_access_key("AKIA_OLD_UNUSED", "Active", old_create_date)]
    }
    mock_client.get_access_key_last_used.return_value = {"AccessKeyLastUsed": {}}

    results = checker._evaluate_user_access_keys("bob", UNUSED_CREDENTIALS_THRESHOLD_DAYS)

    assert len(results) == 1
    assert results[0].status == CheckStatus.FAIL


def test_inactive_key_is_skipped() -> None:
    """
    An already-deactivated access key isn't a finding for this check,
    so it should produce no result at all (not a PASS, not a FAIL).
    """
    checker, mock_client = _checker_with_mocked_client()
    mock_client.list_access_keys.return_value = {
        "AccessKeyMetadata": [_access_key("AKIA_INACTIVE", "Inactive", datetime.now(timezone.utc))]
    }

    results = checker._evaluate_user_access_keys("bob", UNUSED_CREDENTIALS_THRESHOLD_DAYS)

    assert results == []
    mock_client.get_access_key_last_used.assert_not_called()


def test_key_used_within_threshold_passes() -> None:
    """
    A key last used 44 days ago (inside the 45-day CIS threshold)
    should PASS.
    """
    checker, mock_client = _checker_with_mocked_client()
    now: datetime = datetime.now(timezone.utc)
    mock_client.list_access_keys.return_value = {
        "AccessKeyMetadata": [_access_key("AKIA_RECENT", "Active", now - timedelta(days=200))]
    }
    mock_client.get_access_key_last_used.return_value = {
        "AccessKeyLastUsed": {"LastUsedDate": now - timedelta(days=44)}
    }

    results = checker._evaluate_user_access_keys("bob", UNUSED_CREDENTIALS_THRESHOLD_DAYS)

    assert len(results) == 1
    assert results[0].status == CheckStatus.PASS


def test_key_used_at_threshold_fails() -> None:
    """
    A key last used exactly 45 days ago meets the CIS "45 days or
    greater" threshold and should therefore FAIL.
    """
    checker, mock_client = _checker_with_mocked_client()
    now: datetime = datetime.now(timezone.utc)
    mock_client.list_access_keys.return_value = {
        "AccessKeyMetadata": [_access_key("AKIA_THRESHOLD", "Active", now - timedelta(days=200))]
    }
    mock_client.get_access_key_last_used.return_value = {
        "AccessKeyLastUsed": {"LastUsedDate": now - timedelta(days=45)}
    }

    results = checker._evaluate_user_access_keys("bob", UNUSED_CREDENTIALS_THRESHOLD_DAYS)

    assert len(results) == 1
    assert results[0].status == CheckStatus.FAIL


def test_key_used_outside_threshold_fails() -> None:
    """
    A key last used 46 days ago (past the 45-day CIS threshold) should
    FAIL.
    """
    checker, mock_client = _checker_with_mocked_client()
    now: datetime = datetime.now(timezone.utc)
    mock_client.list_access_keys.return_value = {
        "AccessKeyMetadata": [_access_key("AKIA_STALE", "Active", now - timedelta(days=200))]
    }
    mock_client.get_access_key_last_used.return_value = {
        "AccessKeyLastUsed": {"LastUsedDate": now - timedelta(days=46)}
    }

    results = checker._evaluate_user_access_keys("bob", UNUSED_CREDENTIALS_THRESHOLD_DAYS)

    assert len(results) == 1
    assert results[0].status == CheckStatus.FAIL


def test_unused_access_keys_reports_error_on_access_denied() -> None:
    """
    An AccessDenied error while listing users should surface as a
    single ERROR result with the exception detail in `error`, not
    `remediation`.
    """
    checker, mock_client = _checker_with_mocked_client()
    paginator = MagicMock()
    paginator.paginate.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "ListUsers"
    )
    mock_client.get_paginator.return_value = paginator

    results = checker.check_unused_access_keys()

    assert len(results) == 1
    assert results[0].status == CheckStatus.ERROR
    assert "AccessDenied" in results[0].error
    assert results[0].remediation != results[0].error
