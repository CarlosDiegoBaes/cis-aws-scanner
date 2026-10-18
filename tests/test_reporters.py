"""Console, JSON, and HTML reporters share one ScanReport."""

import json

from cis_aws_scanner.models import Finding, ScanReport, Severity, Status
from cis_aws_scanner.reporters import ConsoleReporter, HtmlReporter, JsonReporter
from cis_aws_scanner.scoring import summarize


def _report(findings: list[Finding]) -> ScanReport:
    return ScanReport(
        findings=findings,
        profile="lab",
        region="us-east-1",
        summary=summarize(findings),
        generated_at="2026-01-01T00:00:00+00:00",
    )


def _fail() -> Finding:
    return Finding(
        check_id="1.8",
        title="Password policy requires a minimum length of 14 characters",
        cis_reference="1.8",
        severity=Severity.MEDIUM,
        status=Status.FAIL,
        service="iam",
        resource="<script>alert('xss')</script>",
        evidence="MinimumPasswordLength=8",
        remediation="Set minimum password length to at least 14.",
    )


def test_console_includes_the_score_and_the_fix() -> None:
    text = ConsoleReporter().render(_report([_fail()]))

    assert "Profile: lab" in text
    assert "[FAIL ]" in text
    assert "1.8" in text
    assert "evidence: MinimumPasswordLength=8" in text
    assert "fix: Set minimum password length" in text
    assert "Score: 0/100" in text
    assert "MEDIUM 0 pass / 1 fail / 0 error" in text


def test_console_skips_fix_lines_for_a_pass() -> None:
    finding = Finding(
        check_id="1.4",
        title="No access keys for the root account",
        cis_reference="1.4",
        severity=Severity.CRITICAL,
        status=Status.PASS,
        service="iam",
        resource="root",
        remediation="Delete any root account access keys.",
    )

    text = ConsoleReporter().render(_report([finding]))

    assert "Score: 100/100" in text
    assert "fix:" not in text


def test_json_report_is_structured() -> None:
    payload = json.loads(JsonReporter().render(_report([_fail()])))

    assert payload["profile"] == "lab"
    assert payload["region"] == "us-east-1"
    assert payload["summary"]["failed"] == 1
    assert payload["summary"]["score"] == 0
    assert payload["findings"][0]["evidence"] == "MinimumPasswordLength=8"
    assert payload["findings"][0]["severity"] == "MEDIUM"


def test_html_report_escapes_aws_values_and_shows_the_score() -> None:
    rendered = HtmlReporter().render(_report([_fail()]))

    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "MinimumPasswordLength=8" in rendered
    assert "Score 0/100" in rendered
    assert "MEDIUM" in rendered
    assert 'class="FAIL"' in rendered


def test_html_keeps_braces_in_a_resource_name() -> None:
    finding = Finding(
        check_id="1.10",
        title="MFA",
        cis_reference="1.10",
        severity=Severity.HIGH,
        status=Status.FAIL,
        service="iam",
        resource="user{1}",
        evidence="a{b}",
        remediation="Attach MFA.",
    )

    rendered = HtmlReporter().render(_report([finding]))

    assert "user{1}" in rendered
    assert "a{b}" in rendered


def test_reporters_write_a_file(tmp_path) -> None:
    report = _report([_fail()])
    path = tmp_path / "nested" / "report.json"

    JsonReporter().write(report, path)

    assert json.loads(path.read_text(encoding="utf-8"))["summary"]["failed"] == 1
