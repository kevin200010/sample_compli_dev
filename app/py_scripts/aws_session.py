import boto3
import logging
from typing import Optional
from botocore.exceptions import ProfileNotFound


def get_boto3_session(profile_name: Optional[str] = None) -> boto3.Session:
    """Return a boto3 Session using *profile_name* when available.

    If the named profile cannot be found, a warning is logged and the
    default credential resolution chain is used instead. This allows the
    application to run on environments like EC2/ECS/Lambda where IAM roles
    provide credentials without requiring local AWS profiles.
    """
    if profile_name:
        try:
            return boto3.Session(profile_name=profile_name)
        except ProfileNotFound:
            logging.warning(
                "AWS profile '%s' not found. Falling back to default credentials.",
                profile_name,
            )
    # No profile provided or lookup failed; rely on default chain (env vars, IAM role, etc.)
    return boto3.Session()
