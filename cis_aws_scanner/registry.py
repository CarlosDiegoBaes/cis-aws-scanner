"""A registry that collects check classes and builds instances.

Checks register themselves with a decorator when their module is
imported. The scanner asks the registry for instances, optionally
limited to one or more services. The scanner does not keep its own
hard-coded list of classes.

This is the registry pattern: objects sign up in one place, and the
code that uses them asks for the current list.
"""

from __future__ import annotations

from collections.abc import Sequence

from cis_aws_scanner.check import Check
from cis_aws_scanner.models import Severity

_REQUIRED_ATTRIBUTES: tuple[str, ...] = (
    "id",
    "title",
    "cis_reference",
    "severity",
    "service",
    "remediation",
)

# Reports stay in this order even if the modules are imported differently.
_SERVICE_ORDER: dict[str, int] = {
    "iam": 0,
    "s3": 1,
    "cloudtrail": 2,
    "ec2": 3,
}


class CheckRegistry:
    """An ordered collection of :class:`Check` subclasses."""

    def __init__(self) -> None:
        self._checks: list[type[Check]] = []

    def register(self, check_cls: type[Check]) -> type[Check]:
        """Add ``check_cls`` and return it, so this works as a decorator.

        Registering the same class twice is ignored. A class that is
        missing an interface attribute, or whose severity is not a
        :class:`Severity`, raises ``TypeError``.
        """
        missing = [name for name in _REQUIRED_ATTRIBUTES if not hasattr(check_cls, name)]
        if missing:
            names = ", ".join(missing)
            raise TypeError(f"{check_cls.__name__} is missing: {names}")
        if not isinstance(check_cls.severity, Severity):
            raise TypeError(f"{check_cls.__name__}.severity must be a Severity value")
        if check_cls not in self._checks:
            self._checks.append(check_cls)
        return check_cls

    def known_services(self) -> set[str]:
        """Return the service names of every registered check."""
        return {check_cls.service for check_cls in self._checks}

    def classes(self) -> list[type[Check]]:
        """Return the registered classes in registration order."""
        return list(self._checks)

    def create(self, services: Sequence[str] | None = None) -> list[Check]:
        """Build one instance of each selected check.

        ``services`` is a list of names such as ``["iam", "s3"]``.
        ``None`` selects every registered check.
        """
        wanted = {service.lower() for service in services} if services else None
        selected: list[Check] = []
        for check_cls in self._checks:
            if wanted is not None and check_cls.service not in wanted:
                continue
            selected.append(check_cls())
        selected.sort(
            key=lambda check: (_SERVICE_ORDER.get(check.service, 99), _id_sort_key(check.id))
        )
        return selected

    def __len__(self) -> int:
        return len(self._checks)

    def __str__(self) -> str:
        return f"CheckRegistry({len(self._checks)} checks)"


def _id_sort_key(check_id: str) -> tuple[tuple[int, ...], str]:
    """Sort 1.4 before 1.10, and keep a suffix such as ``multi-region`` after the number.

    ``s3-encryption`` has no dotted number, so it sorts after the
    numbered S3 control.
    """
    head, _separator, tail = check_id.partition("-")
    pieces = head.split(".")
    if pieces and all(piece.isdigit() for piece in pieces):
        return tuple(int(piece) for piece in pieces), tail
    return (999,), check_id


registry = CheckRegistry()


def load_checks() -> CheckRegistry:
    """Import every built-in check module and return the shared registry.

    Importing the package runs each ``@registry.register`` decorator.
    Call this before creating checks. Calling it twice is safe.
    """
    import cis_aws_scanner.checks  # noqa: F401

    return registry
