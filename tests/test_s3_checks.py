"""S3 public access block and default encryption."""

from __future__ import annotations

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from cis_aws_scanner.checks.s3 import S3DefaultEncryptionCheck, S3PublicAccessBlockCheck
from cis_aws_scanner.models import Status

_LOCKED = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def _bucket(session, name: str) -> None:
    session.client("s3").create_bucket(Bucket=name)


def test_no_buckets_passes_both_checks(session) -> None:
    public = S3PublicAccessBlockCheck().run(session)[0]
    encrypted = S3DefaultEncryptionCheck().run(session)[0]

    assert public.status is Status.PASS
    assert encrypted.status is Status.PASS
    assert public.evidence == "no S3 buckets"


def test_missing_public_access_block_fails(session) -> None:
    _bucket(session, "open-bucket")

    result = S3PublicAccessBlockCheck().run(session)[0]

    assert result.status is Status.FAIL
    assert result.resource == "open-bucket"
    assert result.check_id == "2.1.4"
    assert result.cis_reference == "2.1.4"


def test_partial_public_access_block_fails(session) -> None:
    _bucket(session, "partial")
    config = dict(_LOCKED)
    config["RestrictPublicBuckets"] = False
    session.client("s3").put_public_access_block(
        Bucket="partial",
        PublicAccessBlockConfiguration=config,
    )

    result = S3PublicAccessBlockCheck().run(session)[0]

    assert result.status is Status.FAIL
    assert "RestrictPublicBuckets" in result.evidence


def test_full_public_access_block_passes(session) -> None:
    _bucket(session, "locked")
    session.client("s3").put_public_access_block(
        Bucket="locked",
        PublicAccessBlockConfiguration=_LOCKED,
    )

    result = S3PublicAccessBlockCheck().run(session)[0]

    assert result.status is Status.PASS
    assert result.evidence == "all four flags enabled"


def test_missing_public_access_block_error_code_is_a_failure() -> None:
    """Real AWS raises this code when the block was never configured."""
    client = MagicMock()
    client.list_buckets.return_value = {"Buckets": [{"Name": "plain"}]}
    client.get_bucket_location.return_value = {"LocationConstraint": None}
    client.get_public_access_block.side_effect = ClientError(
        {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": "none"}},
        "GetPublicAccessBlock",
    )
    session = MagicMock()
    session.client.return_value = client

    result = S3PublicAccessBlockCheck().run(session)[0]

    assert result.status is Status.FAIL
    assert result.evidence == "no public access block configuration"


def test_bucket_without_encryption_configuration_fails(session) -> None:
    _bucket(session, "plain")

    result = S3DefaultEncryptionCheck().run(session)[0]

    assert result.status is Status.FAIL
    assert result.resource == "plain"
    assert result.check_id == "s3-encryption"
    assert "no v3.0.0 id" in result.cis_reference


def test_bucket_with_default_encryption_passes(session) -> None:
    _bucket(session, "encrypted")
    session.client("s3").put_bucket_encryption(
        Bucket="encrypted",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )

    result = S3DefaultEncryptionCheck().run(session)[0]

    assert result.status is Status.PASS
    assert result.evidence == "SSEAlgorithm=AES256"


def test_encryption_not_found_error_is_a_failure() -> None:
    client = MagicMock()
    client.list_buckets.return_value = {"Buckets": [{"Name": "plain"}]}
    client.get_bucket_location.return_value = {"LocationConstraint": None}
    client.get_bucket_encryption.side_effect = ClientError(
        {
            "Error": {
                "Code": "ServerSideEncryptionConfigurationNotFoundError",
                "Message": "none",
            }
        },
        "GetBucketEncryption",
    )
    session = MagicMock()
    session.client.return_value = client

    result = S3DefaultEncryptionCheck().run(session)[0]

    assert result.status is Status.FAIL
    assert result.evidence == "no default encryption configuration"
