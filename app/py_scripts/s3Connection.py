import os

import boto3

try:
    from boto3.s3.transfer import S3UploadFailedError, TransferConfig
except (ImportError, ModuleNotFoundError):  # pragma: no cover - exercised in tests
    from boto3.s3.transfer import S3UploadFailedError  # type: ignore[attr-defined]

    TransferConfig = None  # type: ignore[assignment]
from botocore.exceptions import ClientError
from types import SimpleNamespace

try:  # pragma: no cover - exercised only when Flask is unavailable
    from flask import current_app
except ModuleNotFoundError:  # pragma: no cover - test safeguard when Flask is absent
    class _StubLogger:
        def info(self, *args, **kwargs):
            return None

        def warning(self, *args, **kwargs):
            return None

        def error(self, *args, **kwargs):
            return None

    current_app = SimpleNamespace(logger=_StubLogger())

from app.py_scripts.aws_session import get_boto3_session
from app.accounts.helpers import ensure_account_bucket

AWS_REGION = os.getenv("AWS_REGION")

# Prefer single-part uploads for artifacts below 5 GiB so that environments
# lacking ``s3:CreateMultipartUpload`` permissions can still persist reports.
# ``upload_file`` will automatically switch back to multipart uploads for
# larger files that exceed this threshold. When :class:`TransferConfig` is not
# available (e.g., boto3 stubs in unit tests) we simply skip the optimisation.
if TransferConfig is not None:
    SINGLE_PART_TRANSFER_CONFIG = TransferConfig(multipart_threshold=5 * 1024**3)
else:  # pragma: no cover - exercised only in stubbed environments
    SINGLE_PART_TRANSFER_CONFIG = None


def upload_to_s3(
    file_path: str,
    bucket_name: str,
    s3_key: str,
    account_id: str,
    user_id: int,
    profile_name: str | None = None,
    region: str | None = AWS_REGION,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
    aws_session_token: str | None = None,
    session: boto3.session.Session | None = None,
) -> str:
    """Upload *file_path* to *bucket_name* using the given credentials.

    The upload leverages either a pre-built :class:`boto3.Session`, explicit
    credentials, or an AWS profile. When *session* is provided it is used
    directly; otherwise explicit credentials take precedence, falling back to
    a profile name.
    :param account_id: Account identifier for logging correlation.
    :param user_id: ID of the authenticated user performing the upload.
    """

    # Ensure the provided bucket belongs to this account and user
    ensure_account_bucket(int(account_id), int(user_id), bucket_name)

    # Reuse a provided session when available. This allows callers to refresh
    # credentials once and share the resulting client across multiple uploads.
    if session is None:
        if aws_access_key_id and aws_secret_access_key:
            session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
            )
        else:
            session = get_boto3_session(profile_name)

    s3_client = (
        session.client("s3", region_name=region)
        if region
        else session.client("s3")
    )

    # Ensure the bucket exists, creating it when absent.
    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code in ("404", "NoSuchBucket"):
            create_kwargs: dict[str, object] = {"Bucket": bucket_name}
            if region and region != "us-east-1":
                create_kwargs["CreateBucketConfiguration"] = {
                    "LocationConstraint": region
                }
            s3_client.create_bucket(**create_kwargs)
        elif error_code in ("403", "AccessDenied", "Forbidden"):
            current_app.logger.warning(
                "HeadBucket access denied; proceeding with upload",
                extra={
                    "account_id": account_id,
                    "bucket": bucket_name,
                    "artifact_key": s3_key,
                },
            )
        else:
            raise

    current_app.logger.info(
        f"Uploading {file_path}",
        extra={
            "account_id": account_id,
            "bucket": bucket_name,
            "artifact_key": s3_key,
        },
    )
    try:
        upload_kwargs: dict[str, object] = {}
        if SINGLE_PART_TRANSFER_CONFIG is not None:
            upload_kwargs["Config"] = SINGLE_PART_TRANSFER_CONFIG
        s3_client.upload_file(file_path, bucket_name, s3_key, **upload_kwargs)
    except (ClientError, S3UploadFailedError) as e:
        current_app.logger.error(
            f"Failed to upload {file_path}: {e}",
            extra={
                "account_id": account_id,
                "bucket": bucket_name,
                "artifact_key": s3_key,
            },
        )
        error = getattr(e, "original_error", e)
        error_code = (
            error.response.get("Error", {}).get("Code")
            if isinstance(error, ClientError)
            else None
        )
        if error_code is None and "AccessDenied" in str(e):
            error_code = "AccessDenied"
        if error_code in ("AccessDenied", "403", "Forbidden"):
            current_app.logger.warning(
                "Retrying upload with single-part PUT after access denial",
                extra={
                    "account_id": account_id,
                    "bucket": bucket_name,
                    "artifact_key": s3_key,
                },
            )
            try:
                with open(file_path, "rb") as artifact:
                    s3_client.put_object(
                        Bucket=bucket_name,
                        Key=s3_key,
                        Body=artifact,
                    )
            except ClientError as retry_error:
                current_app.logger.error(
                    f"Fallback upload failed for {file_path}: {retry_error}",
                    extra={
                        "account_id": account_id,
                        "bucket": bucket_name,
                        "artifact_key": s3_key,
                    },
                )
                if os.path.exists(file_path):
                    current_app.logger.warning(
                        f"Retaining local file {file_path} due to upload failure",
                        extra={
                            "account_id": account_id,
                            "bucket": bucket_name,
                            "artifact_key": s3_key,
                        },
                    )
                raise retry_error
            else:
                current_app.logger.info(
                    f"File {file_path} uploaded via single-part request",
                    extra={
                        "account_id": account_id,
                        "bucket": bucket_name,
                        "artifact_key": s3_key,
                    },
                )
                if os.path.exists(file_path):
                    os.remove(file_path)
                return s3_key
        if os.path.exists(file_path):
            current_app.logger.warning(
                f"Retaining local file {file_path} due to upload failure",
                extra={
                    "account_id": account_id,
                    "bucket": bucket_name,
                    "artifact_key": s3_key,
                },
            )
        raise
    else:
        current_app.logger.info(
            f"File {file_path} uploaded",
            extra={
                "account_id": account_id,
                "bucket": bucket_name,
                "artifact_key": s3_key,
            },
        )
        if os.path.exists(file_path):
            os.remove(file_path)

    return s3_key


def download_from_s3(
    bucket_name,
    s3_key,
    account_id,
    user_id,
    profile_name,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
    aws_session_token: str | None = None,
    region: str | None = AWS_REGION,
):
    """Download a file from S3 using an AWS profile or explicit credentials.

    If *profile_name* refers to a profile that is not configured on the
    machine, a warning is logged and the default credential chain is used
    instead (environment variables, IAM role, etc.). When explicit
    credentials are provided they are used as a fallback so the download
    succeeds even without a local profile.
    """

    # Validate bucket ownership before proceeding
    ensure_account_bucket(int(account_id), int(user_id), bucket_name)

    # Reuse the stored credentials when available to avoid relying on the
    # local profile configuration. This ensures cross-account access works
    # even when the executing environment lacks the profile.
    if aws_access_key_id and aws_secret_access_key:
        session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region_name=region,
        )
    else:
        # Create a session using the profile when present. Falling back to the
        # default credentials ensures the code still runs on EC2/ECS where an
        # IAM role supplies credentials.
        session = get_boto3_session(profile_name)

    s3_client = (
        session.client("s3", region_name=region)
        if region
        else session.client("s3")
    )
    print("Downloading JSON finding...")

    try:
        # Check if the file exists in the S3 bucket
        s3_client.head_object(Bucket=bucket_name, Key=s3_key)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code in ("404", "NoSuchKey"):
            print(
                "The requested file could not be found in Amazon S3. Please check the file name or location."
            )
            return None, "File not found", 404
        else:
            return None, f"An error occurred: {str(e)}", 500

    try:
        # Download the file from S3
        s3_object = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
        file_content = s3_object["Body"].read()
        return file_content, None, 200
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == "NoSuchKey":
            print(
                "The requested file could not be found in Amazon S3. Please check the file name or location."
            )
            return None, "File not found", 404
        return None, f"An error occurred while downloading the file: {str(e)}", 500
    except Exception as e:
        return None, f"An error occurred while downloading the file: {str(e)}", 500

