"""
tests/test_report.py

Unit tests for report rendering and HTML output safety.
"""

from __future__ import annotations

from cis_aws_scanner.models import CheckResult, CheckStatus
from cis_aws_scanner.report import ReportGenerator


def test_html_report_includes_evidence() -> None:
    """The HTML report should expose the evidence supporting a result."""
    result = CheckResult(
        "1.8",
        "Password policy requires a minimum length of 14 characters",
        CheckStatus.FAIL,
        "account",
        "Set minimum password length to at least 14.",
        evidence="MinimumPasswordLength=8",
    )

    rendered = ReportGenerator([result]).to_html()

    assert "<th>Evidence</th>" in rendered
    assert "MinimumPasswordLength=8" in rendered


def test_html_report_escapes_aws_controlled_values() -> None:
    """Attacker- or user-controlled AWS values must be HTML-escaped."""
    result = CheckResult(
        "1.10",
        "MFA check",
        CheckStatus.FAIL,
        "<script>alert('xss')</script>",
        "Attach MFA.",
        evidence="<b>unsafe</b>",
    )

    rendered = ReportGenerator([result]).to_html()

    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "<b>unsafe</b>" not in rendered
    assert "&lt;b&gt;unsafe&lt;/b&gt;" in rendered
