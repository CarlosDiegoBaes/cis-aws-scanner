"""The abstract CIS control.

Every concrete check is a subclass of :class:`Check`. The scanner does
not care which subclass it has: it reads the same attributes and calls
:meth:`Check.run`. That is polymorphism.

``run`` returns a list because one control often applies to many
resources (every IAM user, every bucket, every security group). An
account-level control returns a list of one finding.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from boto3.session import Session

from cis_aws_scanner.models import Finding, Severity, Status


class Check(ABC):
    """One CIS control.

    Subclasses set the class attributes and implement :meth:`run`.
    The registry refuses a class that forgets an attribute, so a new
    check fails loudly instead of showing up blank in a report.
    """

    id: ClassVar[str]
    title: ClassVar[str]
    cis_reference: ClassVar[str]
    severity: ClassVar[Severity]
    service: ClassVar[str]
    remediation: ClassVar[str]

    @abstractmethod
    def run(self, session: Session) -> list[Finding]:
        """Evaluate this control with ``session`` and return findings.

        Catch AWS permission errors inside ``run`` and return an ERROR
        finding. Let unexpected bugs propagate; the scanner turns those
        into an ERROR finding so one broken check does not stop the rest.
        """

    def finding(
        self,
        status: Status,
        resource: str = "account",
        evidence: str = "",
        error: str = "",
        remediation: str | None = None,
    ) -> Finding:
        """Build a finding that copies this check's identity fields.

        Pass ``remediation`` only when the fix depends on the resource,
        for example the user or access key that failed. Otherwise the
        class-level text is used.
        """
        return Finding(
            check_id=self.id,
            title=self.title,
            cis_reference=self.cis_reference,
            severity=self.severity,
            status=status,
            service=self.service,
            resource=resource,
            evidence=evidence,
            remediation=self.remediation if remediation is None else remediation,
            error=error,
        )

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(id={self.id}, service={self.service})"
