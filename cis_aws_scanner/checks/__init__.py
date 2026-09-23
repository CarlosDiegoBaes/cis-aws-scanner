"""
cis_aws_scanner.checks

Individual CIS AWS Foundations Benchmark check modules, one per benchmark
section (IAM, S3, CloudTrail, networking, ...). Each module exposes a
Checker class with a run_all() method returning list[CheckResult].
"""
