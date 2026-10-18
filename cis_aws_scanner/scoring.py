"""Turn a list of findings into a :class:`ScoreSummary`.

The scanner calls this once, after every check has run. Reporters print
the summary; they do not recompute it.
"""

from __future__ import annotations

from cis_aws_scanner.models import Finding, ScoreSummary, Severity, Status

# Heavier findings move the score more. The numbers are small on purpose
# so a reader can recompute a score by hand.
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


def _blank_counts() -> dict[str, int]:
    return {"passed": 0, "failed": 0, "errored": 0}


def summarize(findings: list[Finding]) -> ScoreSummary:
    """Score ``findings`` by severity weight.

    PASS adds its weight to the earned total. FAIL adds its weight only
    to the possible total. ERROR is counted, then ignored by the score.
    """
    by_severity: dict[str, dict[str, int]] = {
        severity.value: _blank_counts() for severity in Severity
    }
    passed = 0
    failed = 0
    errored = 0
    earned = 0
    possible = 0

    for finding in findings:
        bucket = by_severity[finding.severity.value]
        weight = SEVERITY_WEIGHTS[finding.severity]
        if finding.status is Status.PASS:
            passed += 1
            bucket["passed"] += 1
            earned += weight
            possible += weight
        elif finding.status is Status.FAIL:
            failed += 1
            bucket["failed"] += 1
            possible += weight
        else:
            errored += 1
            bucket["errored"] += 1

    score = round(100 * earned / possible) if possible else None
    return ScoreSummary(
        passed=passed,
        failed=failed,
        errored=errored,
        score=score,
        by_severity=by_severity,
    )
