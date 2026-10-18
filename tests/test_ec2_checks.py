"""Security groups open to the world on TCP 22 and TCP 3389."""

from cis_aws_scanner.checks.ec2 import SecurityGroupRdpCheck, SecurityGroupSshCheck
from cis_aws_scanner.models import Status


def _group(session, name: str) -> str:
    ec2 = session.client("ec2")
    created = ec2.create_security_group(GroupName=name, Description=name)
    return created["GroupId"]


def _allow(session, group_id: str, permission: dict) -> None:
    session.client("ec2").authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[permission],
    )


def _tcp(port: int, cidr: str = "0.0.0.0/0") -> dict:
    return {
        "IpProtocol": "tcp",
        "FromPort": port,
        "ToPort": port,
        "IpRanges": [{"CidrIp": cidr}],
    }


def _failed(findings):
    return [finding for finding in findings if finding.status is Status.FAIL]


def test_closed_groups_pass(session) -> None:
    group_id = _group(session, "web")
    _allow(session, group_id, _tcp(80))

    ssh = SecurityGroupSshCheck().run(session)
    rdp = SecurityGroupRdpCheck().run(session)

    assert _failed(ssh) == []
    assert _failed(rdp) == []
    assert ssh[0].status is Status.PASS
    assert ssh[0].check_id == "5.2-22"
    assert rdp[0].cis_reference == "5.2 / 5.3"


def test_ssh_open_to_the_world_fails_only_the_ssh_check(session) -> None:
    group_id = _group(session, "ssh-open")
    _allow(session, group_id, _tcp(22))

    ssh_failures = _failed(SecurityGroupSshCheck().run(session))
    rdp_failures = _failed(SecurityGroupRdpCheck().run(session))

    assert len(ssh_failures) == 1
    assert group_id in ssh_failures[0].resource
    assert "0.0.0.0/0" in ssh_failures[0].evidence
    assert rdp_failures == []


def test_rdp_open_to_the_world_fails(session) -> None:
    group_id = _group(session, "rdp-open")
    _allow(session, group_id, _tcp(3389))

    failures = _failed(SecurityGroupRdpCheck().run(session))

    assert len(failures) == 1
    assert group_id in failures[0].resource
    assert failures[0].check_id == "5.2-3389"


def test_private_ssh_does_not_fail(session) -> None:
    group_id = _group(session, "bastion")
    _allow(session, group_id, _tcp(22, cidr="10.0.0.0/8"))

    assert _failed(SecurityGroupSshCheck().run(session)) == []


def test_port_range_that_includes_ssh_fails(session) -> None:
    group_id = _group(session, "wide")
    _allow(
        session,
        group_id,
        {
            "IpProtocol": "tcp",
            "FromPort": 0,
            "ToPort": 100,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        },
    )

    failures = _failed(SecurityGroupSshCheck().run(session))

    assert len(failures) == 1
    assert group_id in failures[0].resource


def test_all_protocols_open_to_the_world_fails_both_ports(session) -> None:
    group_id = _group(session, "all-open")
    _allow(
        session,
        group_id,
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    )

    assert len(_failed(SecurityGroupSshCheck().run(session))) == 1
    assert len(_failed(SecurityGroupRdpCheck().run(session))) == 1


def test_ipv6_world_on_ssh_fails(session) -> None:
    group_id = _group(session, "ipv6-ssh")
    _allow(
        session,
        group_id,
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        },
    )

    failures = _failed(SecurityGroupSshCheck().run(session))

    assert len(failures) == 1
    assert "::/0" in failures[0].evidence
