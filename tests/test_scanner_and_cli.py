"""Scanner composition and the command-line entry point."""

import json
from pathlib import Path

import pytest

from cis_aws_scanner.check import Check
from cis_aws_scanner.cli import main, normalize_services
from cis_aws_scanner.models import Severity, Status
from cis_aws_scanner.scanner import Scanner


class _OkCheck(Check):
    id = "ok"
    title = "Ok"
    cis_reference = "ok"
    severity = Severity.LOW
    service = "iam"
    remediation = "Nothing to do."

    def run(self, session):
        return [self.finding(Status.PASS, evidence="ok")]


class _BoomCheck(Check):
    id = "boom"
    title = "Boom"
    cis_reference = "boom"
    severity = Severity.LOW
    service = "iam"
    remediation = "Fix the check."

    def run(self, session):
        raise RuntimeError("boom")


def test_scanner_turns_an_unexpected_error_into_a_finding_and_continues(session) -> None:
    report = Scanner(session, checks=[_BoomCheck(), _OkCheck()], profile="lab").run()

    assert [finding.check_id for finding in report.findings] == ["boom", "ok"]
    assert report.findings[0].status is Status.ERROR
    assert report.findings[0].error == "boom"
    assert report.findings[0].remediation == "Fix the check."
    assert report.findings[1].status is Status.PASS
    assert report.profile == "lab"
    assert report.summary.errored == 1
    assert report.summary.passed == 1


def test_scanner_service_filter_skips_other_services(session) -> None:
    session.client("s3").create_bucket(Bucket="plain")
    report = Scanner(session, services=["s3"], region="us-east-1").run()

    assert report.findings
    assert {finding.service for finding in report.findings} == {"s3"}
    assert report.summary.score is not None


def test_normalize_services_splits_commas() -> None:
    assert normalize_services(["IAM, s3", "ec2"]) == ["iam", "s3", "ec2"]
    assert normalize_services(None) is None


def test_cli_json_can_limit_the_scan_to_iam(session, capsys) -> None:
    # ``session`` starts moto before main() builds its own session.
    del session
    code = main(["--format", "json", "--service", "iam", "--region", "us-east-1"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 0
    ids = {finding["check_id"] for finding in payload["findings"]}
    assert "1.5" in ids
    assert "1.4" in ids
    assert "2.1.4" not in ids
    assert payload["summary"]["score"] is not None


def test_cli_rejects_an_unknown_service() -> None:
    with pytest.raises(SystemExit):
        main(["--service", "lambda"])


def test_cli_writes_the_report_file(session, tmp_path: Path, capsys) -> None:
    del session
    destination = tmp_path / "out" / "report.html"
    code = main(
        [
            "--format",
            "html",
            "--service",
            "cloudtrail",
            "--output",
            str(destination),
        ]
    )
    captured = capsys.readouterr()

    assert code == 0
    assert "CIS AWS Foundations Benchmark Report" in destination.read_text(encoding="utf-8")
    assert str(destination) in captured.err
    assert "3.1" in captured.out
