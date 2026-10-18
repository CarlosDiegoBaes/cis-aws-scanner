"""Tests for check registration and service filtering."""

import pytest

from cis_aws_scanner.check import Check
from cis_aws_scanner.models import Severity
from cis_aws_scanner.registry import CheckRegistry, load_checks

EXPECTED_IDS = {
    "1.4",
    "1.5",
    "1.8",
    "1.9",
    "1.10",
    "1.12",
    "2.1.4",
    "s3-encryption",
    "3.1",
    "3.1-multi-region",
    "3.2",
    "5.2-22",
    "5.2-3389",
}


def test_builtin_checks_register_the_expected_controls() -> None:
    loaded = load_checks()
    ids = {check_cls.id for check_cls in loaded.classes()}
    assert ids == EXPECTED_IDS
    assert loaded.known_services() == {"iam", "s3", "cloudtrail", "ec2"}


def test_create_filters_by_service_and_sorts() -> None:
    checks = load_checks().create(["s3", "iam"])
    assert [check.id for check in checks] == [
        "1.4",
        "1.5",
        "1.8",
        "1.9",
        "1.10",
        "1.12",
        "2.1.4",
        "s3-encryption",
    ]


def test_register_rejects_a_class_that_forgets_the_interface() -> None:
    local = CheckRegistry()

    class Incomplete(Check):
        def run(self, session):
            return []

    with pytest.raises(TypeError, match="missing"):
        local.register(Incomplete)


def test_register_rejects_a_severity_that_is_not_the_enum() -> None:
    local = CheckRegistry()

    class BadSeverity(Check):
        id = "bad"
        title = "Bad"
        cis_reference = "bad"
        severity = "HIGH"  # type: ignore[assignment]
        service = "iam"
        remediation = "Fix it."

        def run(self, session):
            return []

    with pytest.raises(TypeError, match="Severity"):
        local.register(BadSeverity)


def test_registering_twice_does_not_duplicate() -> None:
    local = CheckRegistry()

    class Tiny(Check):
        id = "tiny"
        title = "Tiny"
        cis_reference = "tiny"
        severity = Severity.LOW
        service = "iam"
        remediation = "None."

        def run(self, session):
            return []

    local.register(Tiny)
    local.register(Tiny)
    assert len(local) == 1
    assert len(local.create()) == 1
