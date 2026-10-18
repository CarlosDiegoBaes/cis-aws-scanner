"""JSON report for another tool to read."""

from __future__ import annotations

import json

from cis_aws_scanner.models import ScanReport
from cis_aws_scanner.reporters.base import Reporter


class JsonReporter(Reporter):
    """A stable JSON document: metadata, summary, then findings."""

    def render(self, report: ScanReport) -> str:
        payload = {
            "generated_at": report.generated_at,
            "profile": report.profile,
            "region": report.region,
            "summary": report.summary.to_dict(),
            "findings": [finding.to_dict() for finding in report.findings],
        }
        return json.dumps(payload, indent=2)
