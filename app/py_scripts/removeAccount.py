import os

import boto3
from botocore.exceptions import ClientError
from flask import url_for, redirect
from flask_login import current_user

from app import db, app
from app.models.models import Accounts
from app.py_scripts.aws_session import get_boto3_session
from app.accounts.helpers import ensure_account_bucket

FINDINGS_DIR = "findings"


def remove_account(acc_id: int):
    account_details = Accounts.query.get(acc_id)
    s3_bucket = account_details.s3_bucket
    email = current_user.email
    alias_to_remove = account_details.alias
    db.session.delete(account_details)
    filename = f"{email}~{alias_to_remove}.json"
    file_path = os.path.join(app.root_path, FINDINGS_DIR, filename)

    session = get_boto3_session(alias_to_remove)
    if session.get_credentials() is None:
        session = boto3.Session(
            aws_access_key_id=account_details.access_key_id,
            aws_secret_access_key=account_details.secret_access_key,
            region_name=account_details.default_region_name,
        )

    s3_client = session.client("s3", region_name=account_details.default_region_name)

    if s3_bucket:
        try:
            ensure_account_bucket(acc_id, current_user.id, s3_bucket)
            s3_client.delete_object(Bucket=s3_bucket, Key=filename)
            print(f"Deleted {filename} from bucket {s3_bucket}.")
            try:
                s3_client.delete_bucket(Bucket=s3_bucket)
                print(f"Deleted bucket {s3_bucket}.")
            except ClientError as e:
                print(f"Could not delete bucket {s3_bucket}: {e}")
        except (ClientError, PermissionError) as e:
            print(f"Could not delete {filename} from bucket {s3_bucket}: {e}")
    else:
        print("No S3 bucket specified for account.")

    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"Deleted JSON file: {file_path}")
    else:
        print(f"JSON file not found: {file_path}")

    db.session.commit()
    db.session.close()

    return redirect(url_for("account.select_account", email=email))
