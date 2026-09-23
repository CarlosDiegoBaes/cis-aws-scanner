"""
scanner.py

Command-line entry point for the CIS AWS Foundations Benchmark scanner.
Runs the enabled check modules against an AWS account and writes a
report.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Final

import boto3

from cis_aws_scanner.checks.iam_checks import IAMChecker
from cis_aws_scanner.models import CheckResult
from cis_aws_scanner.report import ReportGenerator

DEFAULT_OUTPUT_DIR: Final = "sample_output"


class Scanner(object):
    """
    Orchestrates CIS AWS Foundations Benchmark checks across all enabled
    check modules.

    Attributes:
        _session (boto3.Session): private. The AWS session used for all
            checks.
        _profile (str): private. The AWS CLI profile name in use, for
            display purposes.
    """

    def __init__(self, profile: str | None = None, region: str | None = None) -> None:
        """
        Non-default constructor. Initializes a Scanner instance.

        Parameters:
            profile (str | None): AWS CLI profile to use. Defaults to
                the default profile.
            region (str | None): AWS region to use. Defaults to the
                profile's configured region.
        """
        self._session: boto3.Session = boto3.Session(profile_name=profile, region_name=region)
        self._profile: str = profile if profile is not None else "default"

    @property
    def profile(self) -> str:
        """
        Get the AWS CLI profile name in use.
        """
        return self._profile

    def run(self) -> list[CheckResult]:
        """
        Run all enabled check modules.

        Returns:
            list[CheckResult]: The combined results of every check
                module. Currently only IAM (CIS Section 1) is
                implemented; S3, CloudTrail, and network checks are
                planned next.
        """
        results: list[CheckResult] = []
        iam_checker: IAMChecker = IAMChecker(session=self._session)
        results.extend(iam_checker.run_all())
        return results

    def __str__(self) -> str:
        """
        Return a readable string representation of this scanner.
        """
        return f"Scanner(profile='{self._profile}')"


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments for the scanner.

    Returns:
        argparse.Namespace: The parsed arguments.
    """
    parser = argparse.ArgumentParser(description="CIS AWS Foundations Benchmark scanner")
    parser.add_argument("--profile", type=str, default=None, help="AWS CLI profile to use")
    parser.add_argument("--region", type=str, default=None, help="AWS region to use")
    parser.add_argument(
        "--output-dir",
        type=str,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to write JSON/HTML reports to",
    )
    return parser.parse_args()


def main() -> None:
    """
    Run the scanner end-to-end: execute checks, print a console
    summary, and write JSON and HTML reports to disk.
    """
    args: argparse.Namespace = parse_args()
    scanner: Scanner = Scanner(profile=args.profile, region=args.region)
    results: list[CheckResult] = scanner.run()

    report: ReportGenerator = ReportGenerator(results)
    print(report.to_console())

    output_dir: Path = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report.to_json(output_dir / "report.json")
    report.to_html(output_dir / "report.html")
    print(f"\nJSON and HTML reports written to {output_dir}/")


if __name__ == "__main__":
    main()
