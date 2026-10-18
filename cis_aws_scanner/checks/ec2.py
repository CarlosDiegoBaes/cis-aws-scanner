"""Security group checks for remote admin ports.

CIS v3.0.0 replaced the older "port 22" and "port 3389" controls with
two broader ones: 5.2 (no 0.0.0.0/0 to remote admin ports) and 5.3
(no ::/0 to those ports). This scanner splits that idea back into two
classes, one per port, so a finding names SSH or RDP.

Each class cites 5.2 and 5.3. A rule matches when it covers the port
and opens it to 0.0.0.0/0 or ::/0. A from/to range and protocol ``-1``
(all traffic) count. Only the selected region is scanned.
"""

from __future__ import annotations

from typing import Any

from boto3.session import Session
from botocore.exceptions import ClientError

from cis_aws_scanner.check import Check
from cis_aws_scanner.models import Finding, Severity, Status
from cis_aws_scanner.registry import registry


def _covers_port(permission: dict[str, Any], port: int) -> bool:
    protocol = str(permission.get("IpProtocol", ""))
    if protocol == "-1":
        return True
    if protocol != "tcp":
        return False
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if from_port is None or to_port is None:
        return False
    return int(from_port) <= port <= int(to_port)


def _world_cidrs(permission: dict[str, Any]) -> list[str]:
    cidrs: list[str] = []
    for ip_range in permission.get("IpRanges", []):
        if ip_range.get("CidrIp") == "0.0.0.0/0":
            cidrs.append("0.0.0.0/0")
    for ip_range in permission.get("Ipv6Ranges", []):
        if ip_range.get("CidrIpv6") == "::/0":
            cidrs.append("::/0")
    return cidrs


def _groups_exposing_port(session: Session, port: int) -> list[tuple[str, str]]:
    """Return ``(resource, evidence)`` for groups that expose ``port``.

    ``resource`` is the group id plus the group name, so a report can
    be read without a second lookup.
    """
    client = session.client("ec2")
    groups = client.describe_security_groups().get("SecurityGroups", [])
    exposed: list[tuple[str, str]] = []
    for group in groups:
        group_id = str(group.get("GroupId", ""))
        group_name = str(group.get("GroupName", ""))
        hits: list[str] = []
        for permission in group.get("IpPermissions", []):
            if not _covers_port(permission, port):
                continue
            cidrs = _world_cidrs(permission)
            if cidrs:
                protocol = permission.get("IpProtocol")
                hits.append(f"{protocol} {port} from {', '.join(cidrs)}")
        if hits:
            resource = f"{group_id} ({group_name})" if group_name else group_id
            exposed.append((resource, "; ".join(hits)))
    return exposed


class _OpenAdminPortCheck(Check):
    """Shared runner for one admin port. Subclasses set ``port``."""

    port: int

    def run(self, session: Session) -> list[Finding]:
        region = session.region_name or "unknown"
        try:
            exposed = _groups_exposing_port(session, self.port)
        except ClientError as exc:
            return [self.finding(Status.ERROR, resource=region, error=str(exc))]
        if not exposed:
            return [
                self.finding(
                    Status.PASS,
                    resource=region,
                    evidence=f"no security group exposes tcp/{self.port} to the world",
                )
            ]
        return [
            self.finding(Status.FAIL, resource=resource, evidence=evidence)
            for resource, evidence in exposed
        ]


@registry.register
class SecurityGroupSshCheck(_OpenAdminPortCheck):
    """CIS 5.2 / 5.3: no security group allows the world to reach TCP 22."""

    id = "5.2-22"
    title = "Security groups do not allow the world to reach TCP 22"
    cis_reference = "5.2 / 5.3"
    severity = Severity.HIGH
    service = "ec2"
    remediation = "Remove 0.0.0.0/0 and ::/0 from inbound rules that include TCP 22."
    port = 22


@registry.register
class SecurityGroupRdpCheck(_OpenAdminPortCheck):
    """CIS 5.2 / 5.3: no security group allows the world to reach TCP 3389."""

    id = "5.2-3389"
    title = "Security groups do not allow the world to reach TCP 3389"
    cis_reference = "5.2 / 5.3"
    severity = Severity.HIGH
    service = "ec2"
    remediation = "Remove 0.0.0.0/0 and ::/0 from inbound rules that include TCP 3389."
    port = 3389
