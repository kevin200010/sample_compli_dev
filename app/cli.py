import uuid

import boto3
from botocore.exceptions import ClientError
from flask.cli import with_appcontext

from . import app, db
from app.models.models import Accounts


def _create_bucket(s3_client, bucket_name: str, region: str) -> None:
    """Create *bucket_name* in the specified *region* if it doesn't exist."""
    if region != "us-east-1":
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
    else:
        s3_client.create_bucket(Bucket=bucket_name)


@app.cli.command("fix-s3-buckets")
@with_appcontext
def fix_s3_buckets() -> None:
    """Populate missing or invalid S3 buckets for all accounts."""
    accounts = Accounts.query.all()
    for account in accounts:
        session = boto3.Session(
            aws_access_key_id=account.access_key_id,
            aws_secret_access_key=account.secret_access_key,
            region_name=account.default_region_name,
        )
        s3 = session.client("s3")

        needs_bucket = False
        if not account.s3_bucket:
            needs_bucket = True
        else:
            try:
                s3.head_bucket(Bucket=account.s3_bucket)
            except ClientError:
                needs_bucket = True

        if needs_bucket:
            bucket_name = f"aws-complitru-{uuid.uuid4().hex[:8]}"
            try:
                _create_bucket(s3, bucket_name, account.default_region_name)
            except ClientError as exc:
                app.logger.error(
                    f"Could not create bucket for account {account.id}: {exc}"
                )
                continue
            account.s3_bucket = bucket_name
            db.session.add(account)
            app.logger.info(
                "Assigned new bucket",
                extra={"account_id": account.id, "bucket": bucket_name},
            )

    db.session.commit()
    app.logger.info("S3 bucket update complete")
