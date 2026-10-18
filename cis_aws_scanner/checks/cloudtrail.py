"""CloudTrail checks from CIS AWS Foundations Benchmark v3.0.0.

Control 3.1 says CloudTrail is enabled in all regions. That sentence
covers two facts: a trail is logging, and a trail is multi-region.
They are split into two classes so each class has one job. Both cite
CIS 3.1. Control 3.2 is log file validation, in its own class.

Trails are read from the session's region. A single-region trail whose
home is another region will not appear. Multi-region trails do.
"""

from __future__ import annotations

from typing import Any

from boto3.session import Session
from botocore.exceptions import ClientError

from cis_aws_scanner.check import Check
from cis_aws_scanner.models import Finding, Severity, Status
from cis_aws_scanner.registry import registry


def _unique_trails(trails: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop duplicate trail records that share an ARN."""
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for trail in trails:
        key = str(trail.get("TrailARN") or trail.get("Name") or "")
        if key in seen:
            continue
        seen.add(key)
        unique.append(trail)
    return unique


def _load_trails(session: Session) -> tuple[Any, list[dict[str, Any]]]:
    client = session.client("cloudtrail")
    response = client.describe_trails(includeShadowTrails=True)
    return client, _unique_trails(list(response.get("trailList", [])))


def _trail_name(trail: dict[str, Any]) -> str:
    return str(trail.get("Name") or trail.get("TrailARN") or "unknown")


def _is_logging(client: Any, trail: dict[str, Any]) -> bool:
    name = str(trail.get("TrailARN") or trail.get("Name"))
    status = client.get_trail_status(Name=name)
    return bool(status.get("IsLogging", False))


@registry.register
class CloudTrailLoggingCheck(Check):
    """CIS 3.1, part 1: at least one trail is actively logging."""

    id = "3.1"
    title = "At least one CloudTrail trail is logging"
    cis_reference = "3.1"
    severity = Severity.HIGH
    service = "cloudtrail"
    remediation = (
        "Create a trail and turn logging on. A trail that exists but is stopped does not pass."
    )

    def run(self, session: Session) -> list[Finding]:
        try:
            client, trails = _load_trails(session)
        except ClientError as exc:
            return [self.finding(Status.ERROR, error=str(exc))]
        if not trails:
            return [self.finding(Status.FAIL, evidence="no trails in this region")]

        logging_names: list[str] = []
        errors: list[tuple[str, str]] = []
        for trail in trails:
            name = _trail_name(trail)
            try:
                if _is_logging(client, trail):
                    logging_names.append(name)
            except ClientError as exc:
                errors.append((name, str(exc)))
        if logging_names:
            return [self.finding(Status.PASS, evidence="logging: " + ", ".join(logging_names))]
        if errors:
            name, message = errors[0]
            return [self.finding(Status.ERROR, resource=name, error=message)]
        return [self.finding(Status.FAIL, evidence="trails exist but none are logging")]


@registry.register
class CloudTrailMultiRegionCheck(Check):
    """CIS 3.1, part 2: a trail that is logging is also multi-region."""

    id = "3.1-multi-region"
    title = "A logging CloudTrail trail applies to all regions"
    cis_reference = "3.1"
    severity = Severity.HIGH
    service = "cloudtrail"
    remediation = (
        "Turn on IsMultiRegionTrail for a trail that is logging. "
        "A multi-region trail that is stopped does not pass."
    )

    def run(self, session: Session) -> list[Finding]:
        try:
            client, trails = _load_trails(session)
        except ClientError as exc:
            return [self.finding(Status.ERROR, error=str(exc))]
        if not trails:
            return [self.finding(Status.FAIL, evidence="no trails in this region")]

        for trail in trails:
            if not trail.get("IsMultiRegionTrail"):
                continue
            name = _trail_name(trail)
            try:
                logging = _is_logging(client, trail)
            except ClientError as exc:
                return [self.finding(Status.ERROR, resource=name, error=str(exc))]
            if logging:
                return [
                    self.finding(Status.PASS, resource=name, evidence="multi-region and logging")
                ]
        return [self.finding(Status.FAIL, evidence="no multi-region trail is logging")]


@registry.register
class CloudTrailLogValidationCheck(Check):
    """CIS 3.2: every trail has log file validation enabled.

    One failing trail produces one FAIL finding, so the report names
    the trail to fix. When every trail validates, there is a single PASS.
    No trails is a FAIL: there is nothing whose integrity can be checked.
    """

    id = "3.2"
    title = "CloudTrail log file validation is enabled"
    cis_reference = "3.2"
    severity = Severity.MEDIUM
    service = "cloudtrail"
    remediation = "Enable log file validation on the trail."

    def run(self, session: Session) -> list[Finding]:
        try:
            _client, trails = _load_trails(session)
        except ClientError as exc:
            return [self.finding(Status.ERROR, error=str(exc))]
        if not trails:
            return [self.finding(Status.FAIL, evidence="no trails in this region")]

        failures: list[Finding] = []
        for trail in trails:
            name = _trail_name(trail)
            if trail.get("LogFileValidationEnabled"):
                continue
            failures.append(
                self.finding(
                    Status.FAIL,
                    resource=name,
                    evidence="LogFileValidationEnabled=false",
                )
            )
        if failures:
            return failures
        return [self.finding(Status.PASS, evidence=f"{len(trails)} trail(s) validate log files")]
