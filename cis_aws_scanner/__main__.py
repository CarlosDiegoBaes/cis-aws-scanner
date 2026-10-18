"""Allow ``python -m cis_aws_scanner``."""

from cis_aws_scanner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
