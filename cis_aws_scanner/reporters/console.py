"""Plain-text report for a terminal."""

from __future__ import annotations

from cis_aws_scanner.models import ScanReport, Status
from cis_aws_scanner.reporters.base import Reporter


class ConsoleReporter(Reporter):
    """One line per finding, with evidence and a fix under each failure."""

    def render(self, report: ScanReport) -> str:
        lines: list[str] = [
            "CIS AWS Foundations Benchmark scan",
            f"Profile: {report.profile}    Region: {report.region}",
            f"Generated: {report.generated_at}",
            "",
        ]
        if not report.findings:
            lines.append("No findings. No checks matched the selected services.")
        for finding in report.findings:
            lines.append(str(finding))
            if finding.status is Status.PASS:
                continue
            lines.append(f"        resource: {finding.resource}")
            if finding.evidence:
                lines.append(f"        evidence: {finding.evidence}")
            if finding.remediation:
                lines.append(f"        fix: {finding.remediation}")
            if finding.error:
                lines.append(f"        error: {finding.error}")
        lines.append("")
        lines.append(_summary_line(report))
        lines.append(_severity_line(report))
        return "\n".join(lines)


def _summary_line(report: ScanReport) -> str:
    summary = report.summary
    score = "n/a" if summary.score is None else f"{summary.score}/100"
    return (
        f"Score: {score}    "
        f"{summary.passed} passed, {summary.failed} failed, "
        f"{summary.errored} errored ({len(report.findings)} findings)"
    )


def _severity_line(report: ScanReport) -> str:
    parts: list[str] = []
    for severity, counts in report.summary.by_severity.items():
        if counts["passed"] == 0 and counts["failed"] == 0 and counts["errored"] == 0:
            continue
        passed = counts["passed"]
        failed = counts["failed"]
        errored = counts["errored"]
        parts.append(f"{severity} {passed} pass / {failed} fail / {errored} error")
    if not parts:
        return "By severity: none"
    return "By severity: " + "; ".join(parts)
