"""Shared AWS client settings so stalled API calls fail within a bounded time."""

import boto3
from botocore.config import Config


AWS_CLIENT_CONFIG = Config(
    connect_timeout=5,
    read_timeout=15,
    retries={"mode": "standard", "total_max_attempts": 2},
)


def create_client(service_name, **kwargs):
    return boto3.client(service_name, config=AWS_CLIENT_CONFIG, **kwargs)
