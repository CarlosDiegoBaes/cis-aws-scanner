"""Build sample_output/ from a mocked account.

The account is a mix of passing and failing settings. Nothing here
talks to a real AWS account. Run it from the repo root:

    python generate_sample_output.py
"""

from __future__ import annotations

import os
from pathlib import Path

import boto3
from moto import mock_aws

from cis_aws_scanner.reporters import ConsoleReporter, HtmlReporter, JsonReporter
from cis_aws_scanner.scanner import Scanner

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")


def build_sample_account(session: boto3.Session) -> None:
    """Fill ``session`` with a partly compliant account.

    IAM: password length passes, reuse prevention fails, one console
    user has MFA, one does not, and a service account has a new active
    key plus an inactive key.

    S3: one bucket is locked and encrypted, one is neither.

    CloudTrail: one single-region trail is logging, without log
    validation, so multi-region and validation fail.

    EC2: one security group allows the world to SSH.
    """
    iam = session.client("iam")
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        PasswordReusePrevention=5,
    )

    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Sup3r$ecret!23")
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName="alice-mfa")
    iam.enable_mfa_device(
        UserName="alice",
        SerialNumber=device["VirtualMFADevice"]["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="123456",
    )

    iam.create_user(UserName="bob")
    iam.create_login_profile(UserName="bob", Password="An0therSecret!23")

    iam.create_user(UserName="ci-deploy")
    iam.create_access_key(UserName="ci-deploy")
    inactive = iam.create_access_key(UserName="ci-deploy")["AccessKey"]
    iam.update_access_key(
        UserName="ci-deploy",
        AccessKeyId=inactive["AccessKeyId"],
        Status="Inactive",
    )

    s3 = session.client("s3")
    s3.create_bucket(Bucket="logs-locked")
    s3.put_public_access_block(
        Bucket="logs-locked",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket="logs-locked",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.create_bucket(Bucket="public-data")

    cloudtrail = session.client("cloudtrail")
    cloudtrail.create_trail(
        Name="local",
        S3BucketName="logs-locked",
        IsMultiRegionTrail=False,
        EnableLogFileValidation=False,
    )
    cloudtrail.start_logging(Name="local")

    ec2 = session.client("ec2")
    group = ec2.create_security_group(GroupName="ssh-open", Description="lab ssh")
    ec2.authorize_security_group_ingress(
        GroupId=group["GroupId"],
        IpProtocol="tcp",
        FromPort=22,
        ToPort=22,
        CidrIp="0.0.0.0/0",
    )


def main() -> None:
    """Run the scanner inside moto and write the sample reports."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        build_sample_account(session)
        report = Scanner(session, profile="sample", region="us-east-1").run()
        print(ConsoleReporter().render(report))

        output_dir = Path("sample_output")
        output_dir.mkdir(exist_ok=True)
        JsonReporter().write(report, output_dir / "report.json")
        HtmlReporter().write(report, output_dir / "report.html")


if __name__ == "__main__":
    main()
