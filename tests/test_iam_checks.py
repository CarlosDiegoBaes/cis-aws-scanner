"""IAM checks. moto covers the API. A few age and error cases mock the client.

moto cannot backdate CreateDate or LastUsedDate to an exact day, so the
45-day boundary is tested with a fake client.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from cis_aws_scanner.checks.iam import (
    UNUSED_KEY_DAYS,
    AccessKeyAgeCheck,
    ConsoleMfaCheck,
    PasswordLengthCheck,
    PasswordReuseCheck,
    RootAccessKeyCheck,
    RootMfaCheck,
)
from cis_aws_scanner.models import Status


def _session_for(client: MagicMock) -> MagicMock:
    session = MagicMock()
    session.client.return_value = client
    return session


def _client_error(code: str, operation: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "not authorized"}}, operation)


def test_root_mfa_fails_on_a_fresh_account(session) -> None:
    result = RootMfaCheck().run(session)[0]

    assert result.status is Status.FAIL
    assert result.check_id == "1.5"
    assert result.cis_reference == "1.5"
    assert "AccountMFAEnabled=0" in result.evidence


def test_root_mfa_passes_when_the_summary_says_enabled() -> None:
    client = MagicMock()
    client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}

    result = RootMfaCheck().run(_session_for(client))[0]

    assert result.status is Status.PASS
    assert result.evidence == "AccountMFAEnabled=1"


def test_root_mfa_keeps_remediation_when_the_api_errors() -> None:
    client = MagicMock()
    client.get_account_summary.side_effect = _client_error("AccessDenied", "GetAccountSummary")

    result = RootMfaCheck().run(_session_for(client))[0]

    assert result.status is Status.ERROR
    assert "AccessDenied" in result.error
    assert result.remediation == "Enable a virtual or hardware MFA device on the root account."
    assert result.error != result.remediation


def test_root_access_keys_pass_on_a_fresh_account(session) -> None:
    result = RootAccessKeyCheck().run(session)[0]

    assert result.status is Status.PASS
    assert result.check_id == "1.4"
    assert result.evidence == "AccountAccessKeysPresent=0"


def test_root_access_keys_fail_when_a_key_is_present() -> None:
    client = MagicMock()
    client.get_account_summary.return_value = {"SummaryMap": {"AccountAccessKeysPresent": 1}}

    result = RootAccessKeyCheck().run(_session_for(client))[0]

    assert result.status is Status.FAIL
    assert result.severity.value == "CRITICAL"


def test_password_policy_fails_both_controls_when_it_is_missing(session) -> None:
    length = PasswordLengthCheck().run(session)[0]
    reuse = PasswordReuseCheck().run(session)[0]

    assert length.status is Status.FAIL
    assert reuse.status is Status.FAIL
    assert length.evidence == "no password policy configured"
    assert {length.check_id, reuse.check_id} == {"1.8", "1.9"}


def test_password_policy_can_pass_one_control_and_fail_the_other(session) -> None:
    session.client("iam").update_account_password_policy(
        MinimumPasswordLength=8,
        PasswordReusePrevention=24,
    )

    length = PasswordLengthCheck().run(session)[0]
    reuse = PasswordReuseCheck().run(session)[0]

    assert length.status is Status.FAIL
    assert length.evidence == "MinimumPasswordLength=8"
    assert reuse.status is Status.PASS
    assert reuse.evidence == "PasswordReusePrevention=24"


def test_password_policy_passes_when_both_thresholds_are_met(session) -> None:
    session.client("iam").update_account_password_policy(
        MinimumPasswordLength=14,
        PasswordReusePrevention=24,
    )

    assert PasswordLengthCheck().run(session)[0].status is Status.PASS
    assert PasswordReuseCheck().run(session)[0].status is Status.PASS


def test_password_policy_api_error_stays_an_error() -> None:
    client = MagicMock()
    client.get_account_password_policy.side_effect = _client_error(
        "AccessDenied", "GetAccountPasswordPolicy"
    )

    result = PasswordLengthCheck().run(_session_for(client))[0]

    assert result.status is Status.ERROR
    assert "AccessDenied" in result.error
    assert result.remediation.startswith("Set minimum password length")


def test_console_user_without_mfa_fails(session) -> None:
    iam = session.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Sup3r$ecret!23")

    result = ConsoleMfaCheck().run(session)[0]

    assert result.status is Status.FAIL
    assert result.check_id == "1.10"
    assert result.resource == "alice"
    assert result.evidence == "mfa_device_count=0"
    assert "alice" in result.remediation


def test_console_user_with_mfa_passes(session) -> None:
    iam = session.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Sup3r$ecret!23")
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName="alice-mfa")
    iam.enable_mfa_device(
        UserName="alice",
        SerialNumber=device["VirtualMFADevice"]["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="123456",
    )

    result = ConsoleMfaCheck().run(session)[0]

    assert result.status is Status.PASS
    assert result.evidence == "mfa_device_count=1"


def test_user_without_a_login_profile_passes(session) -> None:
    session.client("iam").create_user(UserName="service-account")

    result = ConsoleMfaCheck().run(session)[0]

    assert result.status is Status.PASS
    assert result.evidence == "no login profile"


def test_console_mfa_has_no_findings_when_there_are_no_users(session) -> None:
    assert ConsoleMfaCheck().run(session) == []


def _access_key(key_id: str, status: str, create_date: datetime) -> dict:
    return {"AccessKeyId": key_id, "Status": status, "CreateDate": create_date}


def _age_session(keys: list[dict], last_used: dict | None) -> tuple[MagicMock, MagicMock]:
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Users": [{"UserName": "bob"}]}]
    client.get_paginator.return_value = paginator
    client.list_access_keys.return_value = {"AccessKeyMetadata": keys}
    if last_used is None:
        client.get_access_key_last_used.return_value = {"AccessKeyLastUsed": {}}
    else:
        client.get_access_key_last_used.return_value = {"AccessKeyLastUsed": last_used}
    return _session_for(client), client


def test_new_never_used_key_passes() -> None:
    now = datetime.now(UTC)
    session, _client = _age_session([_access_key("AKIA_NEW", "Active", now)], None)

    result = AccessKeyAgeCheck().run(session)[0]

    assert result.status is Status.PASS
    assert result.resource == "bob/AKIA_NEW"
    assert result.evidence == "never used; created 0 day(s) ago"


def test_old_never_used_key_fails() -> None:
    created = datetime.now(UTC) - timedelta(days=100)
    session, _client = _age_session([_access_key("AKIA_OLD", "Active", created)], None)

    result = AccessKeyAgeCheck().run(session)[0]

    assert result.status is Status.FAIL
    assert "created 100 day(s) ago" in result.evidence


def test_inactive_key_is_skipped() -> None:
    session, client = _age_session(
        [_access_key("AKIA_INACTIVE", "Inactive", datetime.now(UTC))],
        None,
    )

    assert AccessKeyAgeCheck().run(session) == []
    client.get_access_key_last_used.assert_not_called()


def test_key_used_inside_the_window_passes() -> None:
    now = datetime.now(UTC)
    session, _client = _age_session(
        [_access_key("AKIA_RECENT", "Active", now - timedelta(days=200))],
        {"LastUsedDate": now - timedelta(days=44)},
    )

    result = AccessKeyAgeCheck().run(session)[0]

    assert result.status is Status.PASS
    assert result.evidence == "last used 44 day(s) ago"
    assert UNUSED_KEY_DAYS == 45


def test_key_used_at_the_45_day_threshold_fails() -> None:
    now = datetime.now(UTC)
    session, _client = _age_session(
        [_access_key("AKIA_THRESHOLD", "Active", now - timedelta(days=200))],
        {"LastUsedDate": now - timedelta(days=45)},
    )

    result = AccessKeyAgeCheck().run(session)[0]

    assert result.status is Status.FAIL
    assert result.evidence == "last used 45 day(s) ago"


def test_key_used_outside_the_window_fails() -> None:
    now = datetime.now(UTC)
    session, _client = _age_session(
        [_access_key("AKIA_STALE", "Active", now - timedelta(days=200))],
        {"LastUsedDate": now - timedelta(days=46)},
    )

    assert AccessKeyAgeCheck().run(session)[0].status is Status.FAIL


def test_unused_keys_report_an_error_when_listing_users_is_denied() -> None:
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.side_effect = _client_error("AccessDenied", "ListUsers")
    client.get_paginator.return_value = paginator

    result = AccessKeyAgeCheck().run(_session_for(client))[0]

    assert result.status is Status.ERROR
    assert "AccessDenied" in result.error
    assert result.remediation != result.error
