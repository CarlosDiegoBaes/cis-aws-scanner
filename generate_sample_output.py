"""
generate_sample_output.py

One-off script (not part of the package) that builds a mocked AWS
account with a realistic mix of compliant and non-compliant settings,
runs the scanner against it, and writes the results to sample_output/.
This is what produces the sample_output/report.html and report.json
checked into the repo for demo purposes.
"""

from __future__ import annotations

from pathlib import Path

import boto3
from moto import mock_aws

from cis_aws_scanner.checks.iam_checks import IAMChecker
from cis_aws_scanner.report import ReportGenerator


def build_sample_account() -> boto3.Session:
    """
    Returns:
        boto3.Session: A mocked session with a partially-compliant IAM
            configuration: a decent password policy, one user with MFA,
            one user without, and an old unused access key.
    """
    session: boto3.Session = boto3.Session(region_name="us-east-1")
    iam_client = session.client("iam")

    # Meets the minimum-length control (1.8) but not reuse prevention (1.9),
    # to keep the demo output a realistic mix rather than all-pass.
    iam_client.update_account_password_policy(
        MinimumPasswordLength=14,
        PasswordReusePrevention=5,
    )

    # A compliant user: console access + MFA device attached.
    iam_client.create_user(UserName="alice")
    iam_client.create_login_profile(UserName="alice", Password="Sup3r$ecret!23")
    mfa = iam_client.create_virtual_mfa_device(VirtualMFADeviceName="alice-mfa")
    iam_client.enable_mfa_device(
        UserName="alice",
        SerialNumber=mfa["VirtualMFADevice"]["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="123456",
    )

    # A non-compliant user: console access, no MFA.
    iam_client.create_user(UserName="bob")
    iam_client.create_login_profile(UserName="bob", Password="An0therSecret!23")

    # A service account with two access keys: one brand-new and unused
    # (PASS - it hasn't had time to be used yet) and one already
    # deactivated (skipped entirely - not a finding).
    iam_client.create_user(UserName="ci-deploy")
    iam_client.create_access_key(UserName="ci-deploy")
    inactive_key = iam_client.create_access_key(UserName="ci-deploy")["AccessKey"]
    iam_client.update_access_key(
        UserName="ci-deploy",
        AccessKeyId=inactive_key["AccessKeyId"],
        Status="Inactive",
    )

    return session


def main() -> None:
    """
    Build the mocked account, run the IAM checks, and write the sample
    JSON/HTML reports. Everything happens inside a single mock_aws
    context so the session built in build_sample_account() stays valid
    for the checks that follow.
    """
    with mock_aws():
        session: boto3.Session = build_sample_account()
        checker: IAMChecker = IAMChecker(session=session)
        results = checker.run_all()

        report: ReportGenerator = ReportGenerator(results)
        print(report.to_console())

        output_dir: Path = Path("sample_output")
        output_dir.mkdir(exist_ok=True)
        report.to_json(output_dir / "report.json")
        report.to_html(output_dir / "report.html")


if __name__ == "__main__":
    main()
