"""Command-line entry point.

Examples::

    python -m cis_aws_scanner --profile lab --region us-east-1
    python -m cis_aws_scanner --service iam --service s3 --format json
    python -m cis_aws_scanner --format html --output report.html
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import boto3

from cis_aws_scanner.registry import load_checks
from cis_aws_scanner.reporters import REPORTERS, reporter_for
from cis_aws_scanner.scanner import Scanner


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser. Tests call this to avoid parsing ``sys.argv``."""
    parser = argparse.ArgumentParser(description="Read-only CIS AWS Foundations Benchmark scanner.")
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS CLI profile name. Defaults to the standard credential chain.",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region for regional checks (S3 location, CloudTrail, EC2). Default: us-east-1.",
    )
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=sorted(REPORTERS),
        default="console",
        help="Report format written to stdout. Default: console.",
    )
    parser.add_argument(
        "--service",
        action="append",
        default=None,
        help="Limit the scan to a service: iam, s3, cloudtrail, ec2. Repeat for more than one.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Also write the report to this file. Parent directories are created.",
    )
    return parser


def normalize_services(raw: list[str] | None) -> list[str] | None:
    """Split comma-separated ``--service`` values and lowercase them.

    ``None`` means every service. An empty list after splitting also
    means every service.
    """
    if not raw:
        return None
    services: list[str] = []
    for item in raw:
        for part in item.split(","):
            name = part.strip().lower()
            if name:
                services.append(name)
    return services or None


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the scan, and print a report.

    Returns:
        0 after a scan. Bad arguments make argparse exit before this
        function returns.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    services = normalize_services(args.service)

    loaded = load_checks()
    if services is not None:
        unknown = sorted({name for name in services if name not in loaded.known_services()})
        if unknown:
            known = ", ".join(sorted(loaded.known_services()))
            parser.error(f"Unknown service: {', '.join(unknown)}. Choose from: {known}.")

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    profile = args.profile if args.profile is not None else "default"
    scanner = Scanner(
        session,
        profile=profile,
        region=args.region,
        services=services,
    )
    report = scanner.run()
    rendered = reporter_for(args.output_format).render(report)
    print(rendered)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        print(f"Wrote {path}", file=sys.stderr)
    return 0
