"""Read-only scanner for a subset of the CIS AWS Foundations Benchmark.

The package is organized around a few small ideas:

* :class:`cis_aws_scanner.check.Check` is the abstract control.
* Concrete checks live in :mod:`cis_aws_scanner.checks`, grouped by service.
* :class:`cis_aws_scanner.registry.CheckRegistry` collects those classes.
* :class:`cis_aws_scanner.scanner.Scanner` runs them with one boto3 session.
* Reporters in :mod:`cis_aws_scanner.reporters` print the same results
  as console text, JSON, or HTML.
"""

__version__ = "0.2.0"
