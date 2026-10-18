"""The reporter interface.

A reporter turns a finished :class:`ScanReport` into text. It does not
call AWS and it does not decide pass or fail. Console, JSON, and HTML
are three strategies for the same report: the caller picks one and
calls :meth:`Reporter.render`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from cis_aws_scanner.models import ScanReport


class Reporter(ABC):
    """Render a scan report as text, and optionally write that text."""

    @abstractmethod
    def render(self, report: ScanReport) -> str:
        """Return the report as a string."""

    def write(self, report: ScanReport, path: str | Path) -> None:
        """Render ``report`` and write it to ``path`` as UTF-8 text."""
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(self.render(report), encoding="utf-8")

    def __str__(self) -> str:
        return self.__class__.__name__
