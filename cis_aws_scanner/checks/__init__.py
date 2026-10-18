"""Built-in checks, grouped by AWS service.

Importing this package registers every check on the shared registry.
Add a new control by writing a :class:`~cis_aws_scanner.check.Check`
subclass in the matching service module and decorating it with
``@registry.register``.
"""

from cis_aws_scanner.checks.cloudtrail import (
    CloudTrailLoggingCheck,
    CloudTrailLogValidationCheck,
    CloudTrailMultiRegionCheck,
)
from cis_aws_scanner.checks.ec2 import SecurityGroupRdpCheck, SecurityGroupSshCheck
from cis_aws_scanner.checks.iam import (
    AccessKeyAgeCheck,
    ConsoleMfaCheck,
    PasswordLengthCheck,
    PasswordReuseCheck,
    RootAccessKeyCheck,
    RootMfaCheck,
)
from cis_aws_scanner.checks.s3 import S3DefaultEncryptionCheck, S3PublicAccessBlockCheck

__all__ = [
    "AccessKeyAgeCheck",
    "CloudTrailLogValidationCheck",
    "CloudTrailLoggingCheck",
    "CloudTrailMultiRegionCheck",
    "ConsoleMfaCheck",
    "PasswordLengthCheck",
    "PasswordReuseCheck",
    "RootAccessKeyCheck",
    "RootMfaCheck",
    "S3DefaultEncryptionCheck",
    "S3PublicAccessBlockCheck",
    "SecurityGroupRdpCheck",
    "SecurityGroupSshCheck",
]
