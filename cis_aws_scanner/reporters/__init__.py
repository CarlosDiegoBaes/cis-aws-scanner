"""Reporters: console, JSON, and HTML.

``reporter_for`` is the small strategy selector the CLI uses. The three
classes share :class:`cis_aws_scanner.reporters.base.Reporter`.
"""

from cis_aws_scanner.reporters.base import Reporter
from cis_aws_scanner.reporters.console import ConsoleReporter
from cis_aws_scanner.reporters.html_reporter import HtmlReporter
from cis_aws_scanner.reporters.json_reporter import JsonReporter

REPORTERS: dict[str, type[Reporter]] = {
    "console": ConsoleReporter,
    "json": JsonReporter,
    "html": HtmlReporter,
}


def reporter_for(output_format: str) -> Reporter:
    """Return a reporter for ``console``, ``json``, or ``html``.

    Raises:
        KeyError: If ``output_format`` is not one of those names.
    """
    return REPORTERS[output_format]()


__all__ = [
    "REPORTERS",
    "ConsoleReporter",
    "HtmlReporter",
    "JsonReporter",
    "Reporter",
    "reporter_for",
]
