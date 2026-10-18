"""Shared test setup.

Dummy credentials and a disabled EC2 metadata service keep boto3 from
looking for a real account. moto replaces the AWS API inside each test.
"""

from __future__ import annotations

import os

import boto3
import pytest
from moto import mock_aws

os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"


@pytest.fixture
def session():
    """A moto-backed boto3 session in us-east-1."""
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")
