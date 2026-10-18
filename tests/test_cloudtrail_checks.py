"""CloudTrail logging, multi-region, and log file validation."""

from cis_aws_scanner.checks.cloudtrail import (
    CloudTrailLoggingCheck,
    CloudTrailLogValidationCheck,
    CloudTrailMultiRegionCheck,
)
from cis_aws_scanner.models import Status


def _trail(session, name: str, *, multi_region: bool, validation: bool, logging: bool) -> None:
    session.client("s3").create_bucket(Bucket=f"{name}-logs")
    cloudtrail = session.client("cloudtrail")
    cloudtrail.create_trail(
        Name=name,
        S3BucketName=f"{name}-logs",
        IsMultiRegionTrail=multi_region,
        EnableLogFileValidation=validation,
    )
    if logging:
        cloudtrail.start_logging(Name=name)


def test_no_trails_fail_all_three_checks(session) -> None:
    logging = CloudTrailLoggingCheck().run(session)[0]
    multi = CloudTrailMultiRegionCheck().run(session)[0]
    validation = CloudTrailLogValidationCheck().run(session)[0]

    assert logging.status is Status.FAIL
    assert multi.status is Status.FAIL
    assert validation.status is Status.FAIL
    assert logging.check_id == "3.1"
    assert multi.cis_reference == "3.1"
    assert validation.check_id == "3.2"


def test_stopped_trail_does_not_count_as_enabled(session) -> None:
    _trail(session, "paused", multi_region=True, validation=True, logging=False)

    logging = CloudTrailLoggingCheck().run(session)[0]
    multi = CloudTrailMultiRegionCheck().run(session)[0]

    assert logging.status is Status.FAIL
    assert "none are logging" in logging.evidence
    assert multi.status is Status.FAIL
    # Validation is a setting on the trail, not a question of whether it is logging.
    assert CloudTrailLogValidationCheck().run(session)[0].status is Status.PASS


def test_single_region_trail_without_validation_fails_two_checks(session) -> None:
    _trail(session, "local", multi_region=False, validation=False, logging=True)

    logging = CloudTrailLoggingCheck().run(session)[0]
    multi = CloudTrailMultiRegionCheck().run(session)[0]
    validation = CloudTrailLogValidationCheck().run(session)[0]

    assert logging.status is Status.PASS
    assert "local" in logging.evidence
    assert multi.status is Status.FAIL
    assert validation.status is Status.FAIL
    assert validation.resource == "local"
    assert validation.evidence == "LogFileValidationEnabled=false"


def test_multi_region_trail_with_validation_passes(session) -> None:
    _trail(session, "org", multi_region=True, validation=True, logging=True)

    assert CloudTrailLoggingCheck().run(session)[0].status is Status.PASS
    assert CloudTrailMultiRegionCheck().run(session)[0].status is Status.PASS
    assert CloudTrailLogValidationCheck().run(session)[0].status is Status.PASS
