"""
models.py

Core data models used across the CIS AWS Foundations Benchmark scanner:
the possible outcomes of a check, and the result of running one.
"""

from __future__ import annotations

from enum import Enum


class CheckStatus(Enum):
    """
    Enumerates the possible outcomes of running a single CIS benchmark
    check.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


class CheckResult(object):
    """
    Represents the outcome of a single CIS AWS Foundations Benchmark
    check.

    Attributes:
        _control_id (str): private. The CIS control identifier, e.g. "1.5".
        _description (str): private. Human-readable description of the check.
        _status (CheckStatus): private. Whether the check passed, failed, or errored.
        _resource (str): private. The AWS resource or account evaluated.
        _remediation (str): private. Static guidance for fixing a failed check.
        _error (str): private. The exception message when status is ERROR. Kept
            separate from remediation, which is fix-it guidance, not an error log.
        _evidence (str): private. Optional raw detail backing the result (e.g. the
            specific AWS field value that drove the PASS/FAIL decision).
    """

    def __init__(
        self,
        control_id: str,
        description: str,
        status: CheckStatus,
        resource: str = "account",
        remediation: str = "",
        error: str = "",
        evidence: str = "",
    ) -> None:
        """
        Non-default constructor. Initializes a CheckResult instance.

        Parameters:
            control_id (str): The CIS control identifier, e.g. "1.5".
            description (str): Human-readable description of the check.
            status (CheckStatus): Whether the check passed, failed, or errored.
            resource (str): The AWS resource or account evaluated. Defaults to "account".
            remediation (str): Static guidance for fixing a failed check. Defaults to "".
            error (str): The exception message when status is ERROR. Defaults to "".
            evidence (str): Optional raw detail backing the result. Defaults to "".

        Raises:
            TypeError: If status is not a CheckStatus instance.
        """
        if not isinstance(status, CheckStatus):
            raise TypeError("status must be a CheckStatus instance")

        self._control_id: str = control_id
        self._description: str = description
        self._status: CheckStatus = status
        self._resource: str = resource
        self._remediation: str = remediation
        self._error: str = error
        self._evidence: str = evidence

    @property
    def control_id(self) -> str:
        """
        Get the CIS control identifier.
        """
        return self._control_id

    @property
    def description(self) -> str:
        """
        Get the human-readable check description.
        """
        return self._description

    @property
    def status(self) -> CheckStatus:
        """
        Get the outcome of the check.
        """
        return self._status

    @status.setter
    def status(self, status: CheckStatus) -> None:
        """
        Set the outcome of the check.

        Parameters:
            status (CheckStatus): The new outcome.

        Raises:
            TypeError: If status is not a CheckStatus instance.
        """
        if not isinstance(status, CheckStatus):
            raise TypeError("status must be a CheckStatus instance")
        self._status = status

    @property
    def resource(self) -> str:
        """
        Get the AWS resource or account evaluated.
        """
        return self._resource

    @property
    def remediation(self) -> str:
        """
        Get the remediation guidance for a failed check.
        """
        return self._remediation

    @property
    def error(self) -> str:
        """
        Get the exception message recorded when this check could not be
        evaluated (status is ERROR). Empty for PASS/FAIL results.
        """
        return self._error

    @property
    def evidence(self) -> str:
        """
        Get the raw detail backing this result, if any was recorded.
        """
        return self._evidence

    @property
    def passed(self) -> bool:
        """
        Get whether the check passed.
        """
        return self._status == CheckStatus.PASS

    def to_dict(self) -> dict[str, str]:
        """
        Convert this result into a plain dictionary, suitable for JSON
        output.

        Returns:
            dict[str, str]: The check result as a dictionary of strings.
        """
        return {
            "control_id": self._control_id,
            "description": self._description,
            "status": self._status.value,
            "resource": self._resource,
            "remediation": self._remediation,
            "error": self._error,
            "evidence": self._evidence,
        }

    def __str__(self) -> str:
        """
        Return a readable string representation of the check result.
        """
        base: str = f"[{self._status.value:<5}] {self._control_id:<6} {self._description}"
        if self._status == CheckStatus.ERROR and self._error:
            return f"{base} (error: {self._error})"
        return base
