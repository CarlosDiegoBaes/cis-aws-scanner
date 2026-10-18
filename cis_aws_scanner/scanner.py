"""Run a set of checks against one boto3 session.

:class:`Scanner` is composition, not inheritance. It *has* a session
and a list of checks. It is not a special kind of check.
"""

from __future__ import annotations

from collections.abc import Sequence

from boto3.session import Session

from cis_aws_scanner.check import Check
from cis_aws_scanner.models import Finding, ScanReport, Status
from cis_aws_scanner.registry import load_checks
from cis_aws_scanner.scoring import summarize


class Scanner:
    """Compose a boto3 session with the checks it should run.

    Pass ``checks`` in tests when you want a fake check. Leave it empty
    in the CLI and the scanner loads the registered checks, optionally
    filtered by ``services``.
    """

    def __init__(
        self,
        session: Session,
        checks: Sequence[Check] | None = None,
        profile: str = "default",
        region: str = "us-east-1",
        services: Sequence[str] | None = None,
    ) -> None:
        self._session = session
        self._profile = profile
        self._region = region
        if checks is None:
            self._checks = load_checks().create(services)
        else:
            self._checks = list(checks)

    @property
    def profile(self) -> str:
        """AWS profile name recorded on the report. Does not call AWS."""
        return self._profile

    @property
    def region(self) -> str:
        """Region recorded on the report and used by the session."""
        return self._region

    @property
    def checks(self) -> list[Check]:
        """The check instances this scanner will run, in order."""
        return list(self._checks)

    def run(self) -> ScanReport:
        """Run every check and return a scored report.

        An unexpected exception becomes one ERROR finding for that
        check. The remaining checks still run.
        """
        findings: list[Finding] = []
        for check in self._checks:
            try:
                findings.extend(check.run(self._session))
            except Exception as exc:
                findings.append(check.finding(Status.ERROR, error=str(exc)))
        return ScanReport(
            findings=findings,
            profile=self._profile,
            region=self._region,
            summary=summarize(findings),
        )

    def __str__(self) -> str:
        return (
            f"Scanner(profile={self._profile}, region={self._region}, checks={len(self._checks)})"
        )


if __name__ == "__main__":
    from cis_aws_scanner.cli import main

    raise SystemExit(main())
