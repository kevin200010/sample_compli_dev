import os
import sys
from pathlib import Path
from datetime import datetime as real_datetime
from unittest.mock import MagicMock

# Ensure the application uses a lightweight in-memory database and does not
# attempt any network connections during import.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("FLASK_ENV", "local")
os.environ.setdefault("OPENAI_API_KEY", "test")

# Ensure project root is on the Python path so ``app`` can be imported
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import tests.test_s3_pagination_cleanup as _cleanup_test_module  # noqa: F401

from app.accounts.compliance import run_prowler_checks_concurrently  # noqa: E402
from app.accounts import compliance as compliance_module  # noqa: E402


def test_scan_uses_updated_bucket(tmp_path, monkeypatch):
    """Ensure that scans after an account update use the new bucket."""

    old_bucket = "old-bucket"
    new_bucket = "new-bucket"

    upload_buckets: list[str] = []
    upload_keys: list[str] = []
    client_buckets: list[str] = []

    def fake_upload_to_s3(file_path, bucket_name, s3_key, account_id, user_id, **kwargs):
        upload_buckets.append(bucket_name)
        upload_keys.append(s3_key)
        return s3_key

    class FakeS3Client:
        def list_objects_v2(self, Bucket, Prefix):
            client_buckets.append(Bucket)
            return {"KeyCount": 0}

        def delete_objects(self, Bucket, Delete):
            client_buckets.append(Bucket)
            return {"Deleted": []}

        def generate_presigned_url(self, ClientMethod, Params, ExpiresIn=None):
            client_buckets.append(Params.get("Bucket"))
            return "https://example.com"

    fake_client = FakeS3Client()

    session_calls: list[dict] = []

    class FakeSession:
        def __init__(self, **kwargs):
            session_calls.append(kwargs)

        def client(self, service):
            assert service == "s3"
            return fake_client

    monkeypatch.setattr(compliance_module.boto3, "Session", FakeSession)
    monkeypatch.setattr(compliance_module, "upload_to_s3", fake_upload_to_s3)

    def fake_run_prowler_check(check_id, AWS_ALIAS, user_id, account_id, s3_bucket, env):
        assert env.get("AWS_SESSION_TOKEN") == "session-token"
        report = tmp_path / "report.json"
        report.write_text("[]")
        return str(report), 0

    monkeypatch.setattr(compliance_module, "run_prowler_check", fake_run_prowler_check)

    class FixedDateTime:
        @classmethod
        def utcnow(cls):
            return real_datetime(2023, 1, 2, 3, 4, 5)

        @classmethod
        def now(cls, tz=None):  # pragma: no cover - maintain interface
            return real_datetime(2023, 1, 2, 3, 4, 5)

    def fake_generate_reports(
        input_file_path, output_dir, AWS_ALIAS, user_id, storage_prefix=None
    ):
        assert storage_prefix and storage_prefix.endswith("/")
        return [], [str(tmp_path / "dummy.pdf")]

    monkeypatch.setattr(compliance_module, "generate_reports", fake_generate_reports)
    monkeypatch.setattr(compliance_module, "datetime", FixedDateTime)

    monkeypatch.setattr(compliance_module, "ensure_account_bucket", lambda *a, **k: None)

    account = type("Account", (), {})()
    account.aws_prowler_check = ""
    account.aws_prowler_check_date_created = None
    account.aws_prowler_compliance_report = ""

    query_mock = MagicMock()
    query_mock.get.return_value = account
    monkeypatch.setattr(
        compliance_module, "Accounts", type("Accounts", (), {"query": query_mock})
    )

    monkeypatch.setattr(compliance_module.db.session, "commit", lambda: None)

    # Trigger scan with updated credentials and bucket name
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    run_prowler_checks_concurrently(
        [],
        "new_access_key",
        "new_secret_key",
        "us-east-1",
        "alias",
        user_id=1,
        s3_bucket=new_bucket,
        account_id=1,
        aws_session_token="session-token",
    )

    all_buckets = upload_buckets + client_buckets
    assert new_bucket in all_buckets
    assert old_bucket not in all_buckets
    expected_prefix = "Prowler/reports/report-2023-01-02-03-04-05/"
    assert all(key.startswith(expected_prefix) for key in upload_keys)
    assert session_calls == [
        {
            "aws_access_key_id": "new_access_key",
            "aws_secret_access_key": "new_secret_key",
            "region_name": "us-east-1",
            "aws_session_token": "session-token",
        }
    ]
