"""Data the scanner passes between checks, the score, and the reporters.

These are plain dataclasses. A check builds a :class:`Finding`. The
scanner gathers findings into a :class:`ScanReport`. Reporters only read
that report; they do not call AWS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class Status(Enum):
    """Outcome of evaluating one resource against one control."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


class Severity(Enum):
    """How serious a failed control is, for scoring and triage.

    These labels are this project's rating. CIS publishes the control
    text; it does not ship these four buckets.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class Finding:
    """The result of one check against one resource.

    ``remediation`` is always the static "how to fix this" text.
    ``error`` is set only when ``status`` is ERROR, and it holds the
    exception message. Keeping them apart means a permissions failure
    does not overwrite the fix-it guidance.

    ``evidence`` is the raw value that drove a PASS or FAIL, such as
    ``MinimumPasswordLength=8``.
    """

    check_id: str
    title: str
    cis_reference: str
    severity: Severity
    status: Status
    service: str
    resource: str = "account"
    evidence: str = ""
    remediation: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, str]:
        """Return JSON-friendly strings for every field."""
        return {
            "check_id": self.check_id,
            "title": self.title,
            "cis_reference": self.cis_reference,
            "severity": self.severity.value,
            "status": self.status.value,
            "service": self.service,
            "resource": self.resource,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "error": self.error,
        }

    def __str__(self) -> str:
        return (
            f"[{self.status.value:<5}] {self.check_id:<16} "
            f"{self.severity.value:<8} {self.service:<11} {self.title}"
        )


@dataclass(frozen=True)
class ScoreSummary:
    """Pass, fail, and error counts, plus a 0-100 score.

    The score is the share of severity weight that passed. A CRITICAL
    finding weighs more than a LOW one, so fixing a root-account failure
    moves the score more than fixing a password-policy failure.

    Weights: CRITICAL 4, HIGH 3, MEDIUM 2, LOW 1.

    ERROR findings are left out of the score. The scanner could not
    judge them, so they should not look like a pass or a fail.
    ``score`` is None when every finding errored, or when there are
    no findings.
    """

    passed: int
    failed: int
    errored: int
    score: int | None
    by_severity: dict[str, dict[str, int]]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-friendly summary."""
        return {
            "passed": self.passed,
            "failed": self.failed,
            "errored": self.errored,
            "score": self.score,
            "by_severity": self.by_severity,
        }


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class ScanReport:
    """Everything a reporter needs after a scan finishes."""

    findings: list[Finding]
    profile: str
    region: str
    summary: ScoreSummary
    generated_at: str = field(default_factory=_utc_now)

    def __str__(self) -> str:
        score = "n/a" if self.summary.score is None else str(self.summary.score)
        return (
            f"ScanReport(profile={self.profile}, region={self.region}, "
            f"findings={len(self.findings)}, score={score})"
        )
