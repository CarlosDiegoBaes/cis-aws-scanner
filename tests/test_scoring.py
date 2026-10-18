"""Unit tests for the severity-weighted score."""

from cis_aws_scanner.models import Finding, Severity, Status
from cis_aws_scanner.scoring import summarize


def _finding(severity: Severity, status: Status) -> Finding:
    return Finding(
        check_id="x",
        title="Example",
        cis_reference="x",
        severity=severity,
        status=status,
        service="iam",
    )


def test_score_weights_a_critical_failure_more_than_a_medium_pass() -> None:
    """CRITICAL is weight 4 and MEDIUM is weight 2, so 2 / 6 rounds to 33."""
    summary = summarize(
        [
            _finding(Severity.CRITICAL, Status.FAIL),
            _finding(Severity.MEDIUM, Status.PASS),
        ]
    )

    assert summary.passed == 1
    assert summary.failed == 1
    assert summary.errored == 0
    assert summary.score == 33
    assert summary.by_severity["CRITICAL"]["failed"] == 1
    assert summary.by_severity["MEDIUM"]["passed"] == 1


def test_errors_are_left_out_of_the_score() -> None:
    """An ERROR is counted, but it does not change the percentage."""
    summary = summarize(
        [
            _finding(Severity.HIGH, Status.PASS),
            _finding(Severity.HIGH, Status.ERROR),
        ]
    )

    assert summary.score == 100
    assert summary.errored == 1
    assert summary.by_severity["HIGH"]["errored"] == 1


def test_score_is_none_when_nothing_could_be_judged() -> None:
    assert summarize([]).score is None
    assert summarize([_finding(Severity.LOW, Status.ERROR)]).score is None
