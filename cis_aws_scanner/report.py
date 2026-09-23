"""
report.py

Renders CIS AWS Foundations Benchmark scan results to the console, to
JSON, and to a simple static HTML report.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Final

from cis_aws_scanner.models import CheckResult, CheckStatus

_HTML_TEMPLATE: Final = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CIS AWS Foundations Benchmark Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; color: #1a1a1a; }}
  h1 {{ font-size: 1.4rem; }}
  .meta {{ color: #666; margin-bottom: 1.5rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #e2e2e2; font-size: 0.9rem; }}
  th {{ background: #f5f5f5; }}
  .PASS {{ color: #157f3c; font-weight: 600; }}
  .FAIL {{ color: #b3261e; font-weight: 600; }}
  .ERROR {{ color: #a06c00; font-weight: 600; }}
  .summary {{ margin-bottom: 1rem; font-size: 0.95rem; }}
</style>
</head>
<body>
<h1>CIS AWS Foundations Benchmark Report</h1>
<div class="meta">Generated {generated_at}</div>
<div class="summary">{pass_count} passed &middot; {fail_count} failed &middot; {error_count} errored ({total} checks)</div>
<table>
<tr><th>Control</th><th>Status</th><th>Description</th><th>Resource</th><th>Remediation</th><th>Error</th></tr>
{rows}
</table>
</body>
</html>
"""


class ReportGenerator(object):
    """
    Renders a collection of CheckResult objects into console, JSON, or
    HTML output.

    Attributes:
        _results (list[CheckResult]): private. The check results to
            render.
    """

    def __init__(self, results: list[CheckResult]) -> None:
        """
        Non-default constructor. Initializes a ReportGenerator instance.

        Parameters:
            results (list[CheckResult]): The check results to render.
        """
        self._results: list[CheckResult] = results

    @property
    def results(self) -> list[CheckResult]:
        """
        Get the check results held by this report.
        """
        return self._results

    def _counts(self) -> dict[str, int]:
        """
        Returns:
            dict[str, int]: The number of results per CheckStatus, keyed
                by status value.
        """
        counts: dict[str, int] = {status.value: 0 for status in CheckStatus}
        for result in self._results:
            counts[result.status.value] += 1
        return counts

    def to_console(self) -> str:
        """
        Render the results as a plain-text summary suitable for
        printing.

        Returns:
            str: The rendered report text.
        """
        lines: list[str] = [str(result) for result in self._results]
        counts: dict[str, int] = self._counts()
        lines.append("")
        lines.append(
            f"{counts['PASS']} passed, {counts['FAIL']} failed, "
            f"{counts['ERROR']} errored ({len(self._results)} checks total)"
        )
        return "\n".join(lines)

    def to_json(self, output_path: str | Path | None = None) -> str:
        """
        Render the results as a JSON string, optionally writing to a
        file.

        Parameters:
            output_path (str | Path | None): If provided, the JSON is
                also written here.

        Returns:
            str: The rendered JSON text.
        """
        payload: dict[str, object] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": self._counts(),
            "results": [result.to_dict() for result in self._results],
        }
        rendered: str = json.dumps(payload, indent=2)
        if output_path is not None:
            Path(output_path).write_text(rendered, encoding="utf-8")
        return rendered

    def to_html(self, output_path: str | Path | None = None) -> str:
        """
        Render the results as a static HTML report, optionally writing
        to a file.

        Parameters:
            output_path (str | Path | None): If provided, the HTML is
                also written here.

        Returns:
            str: The rendered HTML text.
        """
        counts: dict[str, int] = self._counts()
        row_html: list[str] = []
        for result in self._results:
            # Every value below can, in principle, come from attacker- or
            # user-controlled AWS data (an IAM username, for instance), so
            # everything is HTML-escaped before being embedded in markup.
            row_html.append(
                "<tr>"
                f"<td>{escape(result.control_id)}</td>"
                f'<td class="{escape(result.status.value)}">{escape(result.status.value)}</td>'
                f"<td>{escape(result.description)}</td>"
                f"<td>{escape(result.resource)}</td>"
                f"<td>{escape(result.remediation)}</td>"
                f"<td>{escape(result.error)}</td>"
                "</tr>"
            )
        rendered: str = _HTML_TEMPLATE.format(
            generated_at=datetime.now(timezone.utc).isoformat(),
            pass_count=counts["PASS"],
            fail_count=counts["FAIL"],
            error_count=counts["ERROR"],
            total=len(self._results),
            rows="\n".join(row_html),
        )
        if output_path is not None:
            Path(output_path).write_text(rendered, encoding="utf-8")
        return rendered

    def __str__(self) -> str:
        """
        Return a readable string representation of this report
        generator.
        """
        counts: dict[str, int] = self._counts()
        return f"ReportGenerator({len(self._results)} results: {counts})"
