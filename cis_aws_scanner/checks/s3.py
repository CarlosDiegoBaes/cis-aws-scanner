"""S3 checks.

CIS v3.0.0 control 2.1.4 says every bucket's Block Public Access
settings are on. This module checks the four bucket-level flags.

Default encryption is different. v3.0.0 does not number an
"encryption at rest" control, because Amazon S3 now applies SSE-S3
when a bucket has no encryption configuration. The encryption check
is still here: an explicit configuration is a useful signal, and a
bucket can be pointed at a key on purpose. The finding says it is a
best practice, not a v3.0.0 control id. See the README limitations.
"""

from __future__ import annotations

from typing import Any

from boto3.session import Session
from botocore.exceptions import ClientError

from cis_aws_scanner.check import Check
from cis_aws_scanner.models import Finding, Severity, Status
from cis_aws_scanner.registry import registry

_PUBLIC_ACCESS_FLAGS: tuple[str, ...] = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


def _error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))


def _bucket_names(client: Any) -> list[str]:
    response = client.list_buckets()
    return [str(bucket["Name"]) for bucket in response.get("Buckets", [])]


def _client_for_bucket(session: Session, bucket: str) -> Any:
    """Return an S3 client in the bucket's own region.

    ``GetPublicAccessBlock`` and ``GetBucketEncryption`` must be sent
    to the region that stores the bucket. ``us-east-1`` is stored as a
    null location constraint.
    """
    locator = session.client("s3")
    location = locator.get_bucket_location(Bucket=bucket).get("LocationConstraint")
    region = location or "us-east-1"
    return session.client("s3", region_name=region)


@registry.register
class S3PublicAccessBlockCheck(Check):
    """CIS 2.1.4: each bucket blocks all four public-access paths.

    A missing configuration is a failure. AWS treats a missing block
    as "not blocking", not as "all flags on". An account with no
    buckets passes, because there is nothing to expose.
    """

    id = "2.1.4"
    title = "S3 buckets block public access"
    cis_reference = "2.1.4"
    severity = Severity.HIGH
    service = "s3"
    remediation = (
        "Turn on BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, "
        "and RestrictPublicBuckets for the bucket."
    )

    def run(self, session: Session) -> list[Finding]:
        try:
            names = _bucket_names(session.client("s3"))
        except ClientError as exc:
            return [self.finding(Status.ERROR, error=str(exc))]
        if not names:
            return [self.finding(Status.PASS, evidence="no S3 buckets")]

        findings: list[Finding] = []
        for name in names:
            findings.append(self._evaluate_bucket(session, name))
        return findings

    def _evaluate_bucket(self, session: Session, bucket: str) -> Finding:
        try:
            client = _client_for_bucket(session, bucket)
            config = client.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            if _error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
                return self.finding(
                    Status.FAIL,
                    resource=bucket,
                    evidence="no public access block configuration",
                )
            return self.finding(Status.ERROR, resource=bucket, error=str(exc))

        off = [flag for flag in _PUBLIC_ACCESS_FLAGS if not config.get(flag)]
        if off:
            return self.finding(
                Status.FAIL,
                resource=bucket,
                evidence="off: " + ", ".join(off),
            )
        return self.finding(Status.PASS, resource=bucket, evidence="all four flags enabled")


@registry.register
class S3DefaultEncryptionCheck(Check):
    """Each bucket has an explicit default encryption rule.

    This is not a numbered CIS v3.0.0 control. SSE-S3 is the service
    default even when this API returns no configuration. The check
    fails closed on a missing configuration so a lab account still
    shows the gap. AES256 and aws:kms both pass.
    """

    id = "s3-encryption"
    title = "S3 buckets have default encryption configured"
    cis_reference = "best practice (no v3.0.0 id)"
    severity = Severity.MEDIUM
    service = "s3"
    remediation = (
        "Set a default encryption rule on the bucket (SSE-S3 or SSE-KMS). "
        "This check is a best practice; CIS v3.0.0 does not number it."
    )

    def run(self, session: Session) -> list[Finding]:
        try:
            names = _bucket_names(session.client("s3"))
        except ClientError as exc:
            return [self.finding(Status.ERROR, error=str(exc))]
        if not names:
            return [self.finding(Status.PASS, evidence="no S3 buckets")]

        findings: list[Finding] = []
        for name in names:
            findings.append(self._evaluate_bucket(session, name))
        return findings

    def _evaluate_bucket(self, session: Session, bucket: str) -> Finding:
        try:
            client = _client_for_bucket(session, bucket)
            rules = client.get_bucket_encryption(Bucket=bucket)[
                "ServerSideEncryptionConfiguration"
            ]["Rules"]
        except ClientError as exc:
            if _error_code(exc) == "ServerSideEncryptionConfigurationNotFoundError":
                return self.finding(
                    Status.FAIL,
                    resource=bucket,
                    evidence="no default encryption configuration",
                )
            return self.finding(Status.ERROR, resource=bucket, error=str(exc))

        algorithms = []
        for rule in rules:
            default = rule.get("ApplyServerSideEncryptionByDefault", {})
            algorithm = default.get("SSEAlgorithm")
            if algorithm:
                algorithms.append(str(algorithm))
        if not algorithms:
            return self.finding(
                Status.FAIL,
                resource=bucket,
                evidence="encryption rules present but no SSEAlgorithm",
            )
        return self.finding(
            Status.PASS,
            resource=bucket,
            evidence="SSEAlgorithm=" + ",".join(algorithms),
        )
