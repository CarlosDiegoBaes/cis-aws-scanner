"""A single static HTML file.

Every value that came from AWS is escaped. An IAM user name, a bucket
name, or an error string can contain ``<`` or ``&``. Those characters
must not become markup.
"""

from __future__ import annotations

from html import escape

from cis_aws_scanner.models import ScanReport
from cis_aws_scanner.reporters.base import Reporter

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CIS AWS Foundations Benchmark Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; color: #1a1a1a; }}
  h1 {{ font-size: 1.4rem; }}
  .meta, .note {{ color: #555; }}
  .note {{ margin-bottom: 1rem; max-width: 46rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #e2e2e2;
            font-size: 0.9rem; vertical-align: top; }}
  th {{ background: #f5f5f5; }}
  .PASS {{ color: #157f3c; font-weight: 600; }}
  .FAIL {{ color: #b3261e; font-weight: 600; }}
  .ERROR {{ color: #a06c00; font-weight: 600; }}
  .summary {{ margin-bottom: 0.5rem; font-size: 0.95rem; }}
</style>
</head>
<body>
<h1>CIS AWS Foundations Benchmark Report</h1>
<div class="meta">Profile {profile} &middot; Region {region} &middot; Generated {generated_at}</div>
<div class="summary">
  Score {score} &middot; {passed} passed &middot; {failed} failed
  &middot; {errored} errored ({total} findings)
</div>
<p class="note">
  Read-only configuration review. A FAIL is a control that did not match,
  not proof that an attacker is in the account.
</p>
<table>
<tr>
  <th>Check</th><th>CIS</th><th>Severity</th><th>Status</th><th>Service</th>
  <th>Resource</th><th>Evidence</th><th>Remediation</th><th>Error</th>
</tr>
{rows}
</table>
</body>
</html>
"""


def _html(value: object) -> str:
    """Escape AWS-provided text before it is placed in markup."""
    return escape(str(value))


class HtmlReporter(Reporter):
    """Render the report as a small HTML table."""

    def render(self, report: ScanReport) -> str:
        rows: list[str] = []
        for finding in report.findings:
            status = _html(finding.status.value)
            rows.append(
                "<tr>"
                f"<td>{_html(finding.check_id)}<br>{_html(finding.title)}</td>"
                f"<td>{_html(finding.cis_reference)}</td>"
                f"<td>{_html(finding.severity.value)}</td>"
                f'<td class="{status}">{status}</td>'
                f"<td>{_html(finding.service)}</td>"
                f"<td>{_html(finding.resource)}</td>"
                f"<td>{_html(finding.evidence)}</td>"
                f"<td>{_html(finding.remediation)}</td>"
                f"<td>{_html(finding.error)}</td>"
                "</tr>"
            )
        summary = report.summary
        score = "n/a" if summary.score is None else f"{summary.score}/100"
        return _HTML_TEMPLATE.format(
            profile=_html(report.profile),
            region=_html(report.region),
            generated_at=_html(report.generated_at),
            score=score,
            passed=summary.passed,
            failed=summary.failed,
            errored=summary.errored,
            total=len(report.findings),
            rows="\n".join(rows),
        )
