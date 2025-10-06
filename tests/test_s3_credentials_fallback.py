import io
import json
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

try:  # pragma: no cover - executed only when boto3 is installed
    from boto3.s3.transfer import S3UploadFailedError
except ModuleNotFoundError:  # pragma: no cover - exercised in the test environment
    fake_boto3 = ModuleType("boto3")
    fake_s3 = ModuleType("boto3.s3")
    fake_transfer = ModuleType("boto3.s3.transfer")

    class S3UploadFailedError(Exception):  # type: ignore[no-redef]
        """Lightweight stand-in mirroring boto3's upload failure exception."""

        def __init__(self, message: str | None = None, *, original_error=None, **kwargs):
            super().__init__(message or "S3 upload failed")
            self.original_error = original_error

    class _StubSession:
        def __init__(self, *args, **kwargs):  # pragma: no cover - defensive
            raise RuntimeError("boto3 Session should be monkeypatched during tests")

        def client(self, *args, **kwargs):  # pragma: no cover - defensive
            raise RuntimeError("boto3 Session should be monkeypatched during tests")

    fake_transfer.S3UploadFailedError = S3UploadFailedError
    fake_s3.transfer = fake_transfer
    fake_boto3.s3 = fake_s3
    fake_boto3.Session = _StubSession
    fake_session = ModuleType("boto3.session")
    fake_session.Session = _StubSession
    fake_boto3.session = fake_session

    sys.modules["boto3"] = fake_boto3
    sys.modules["boto3.s3"] = fake_s3
    sys.modules["boto3.s3.transfer"] = fake_transfer
    sys.modules["boto3.session"] = fake_session

    from boto3.s3.transfer import S3UploadFailedError

# Ensure the application uses test-friendly configuration before importing app modules
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("FLASK_ENV", "local")
os.environ.setdefault("OPENAI_API_KEY", "test")

# Make project importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:  # pragma: no cover - prefer real package when available
    from app.py_scripts import s3Connection  # type: ignore[attr-defined]  # noqa: E402
except ModuleNotFoundError as import_error:  # pragma: no cover - fallback for missing deps
    if import_error.name != "flask":
        raise

    import importlib.util

    project_root = Path(__file__).resolve().parents[1]

    botocore_module = ModuleType("botocore")
    exceptions_module = ModuleType("botocore.exceptions")

    class ClientError(Exception):  # type: ignore[no-redef]
        def __init__(self, error_response, operation_name):
            super().__init__(error_response)
            self.response = error_response
            self.operation_name = operation_name

    class ProfileNotFound(Exception):  # type: ignore[no-redef]
        """Raised when the requested profile is unavailable."""

    exceptions_module.ClientError = ClientError
    exceptions_module.ProfileNotFound = ProfileNotFound

    botocore_module.exceptions = exceptions_module

    sys.modules["botocore"] = botocore_module
    sys.modules["botocore.exceptions"] = exceptions_module

    fake_app = ModuleType("app")
    fake_app.__path__ = [str(project_root / "app")]
    fake_py_scripts = ModuleType("app.py_scripts")
    fake_py_scripts.__path__ = []
    fake_accounts = ModuleType("app.accounts")
    fake_accounts.__path__ = []

    sys.modules["app"] = fake_app
    sys.modules["app.py_scripts"] = fake_py_scripts
    sys.modules["app.accounts"] = fake_accounts

    helpers_module = ModuleType("app.accounts.helpers")

    def ensure_account_bucket(*args, **kwargs):  # noqa: ANN001, D401 - simple stub
        """Test stub that performs no validation."""

        return None

    helpers_module.ensure_account_bucket = ensure_account_bucket

    sys.modules["app.accounts.helpers"] = helpers_module
    fake_accounts.helpers = helpers_module

    aws_session_spec = importlib.util.spec_from_file_location(
        "app.py_scripts.aws_session", project_root / "app" / "py_scripts" / "aws_session.py"
    )
    aws_session_module = importlib.util.module_from_spec(aws_session_spec)
    assert aws_session_spec and aws_session_spec.loader
    sys.modules["app.py_scripts.aws_session"] = aws_session_module
    aws_session_spec.loader.exec_module(aws_session_module)
    fake_py_scripts.aws_session = aws_session_module

    s3_connection_spec = importlib.util.spec_from_file_location(
        "app.py_scripts.s3Connection", project_root / "app" / "py_scripts" / "s3Connection.py"
    )
    s3Connection = importlib.util.module_from_spec(s3_connection_spec)
    assert s3_connection_spec and s3_connection_spec.loader
    sys.modules["app.py_scripts.s3Connection"] = s3Connection
    s3_connection_spec.loader.exec_module(s3Connection)
    fake_py_scripts.s3Connection = s3Connection


class DummyLogger:
    def info(self, *args, **kwargs):
        return None

    def warning(self, *args, **kwargs):
        return None

    def error(self, *args, **kwargs):
        return None


@pytest.fixture(autouse=True)
def stub_current_app(monkeypatch):
    monkeypatch.setattr(
        s3Connection,
        "current_app",
        SimpleNamespace(logger=DummyLogger()),
    )


class DummySessionWithoutCredentials:
    def get_credentials(self):
        return None

    def client(self, *args, **kwargs):  # pragma: no cover - should not be called
        raise AssertionError("Fallback session should be constructed with stored credentials")


def test_download_from_s3_retries_with_explicit_credentials(monkeypatch):
    """Ensure downloads succeed when the stored profile lacks credentials."""

    monkeypatch.setattr(
        s3Connection,
        "get_boto3_session",
        lambda profile_name: DummySessionWithoutCredentials(),
    )
    monkeypatch.setattr(
        s3Connection,
        "ensure_account_bucket",
        lambda *args, **kwargs: None,
    )

    session_calls: list[dict] = []
    client_calls: list[tuple[str, str | None]] = []
    head_calls: list[tuple[str, str]] = []
    get_calls: list[tuple[str, str]] = []

    class FakeS3Client:
        def head_object(self, Bucket, Key):
            head_calls.append((Bucket, Key))

        def get_object(self, Bucket, Key):
            get_calls.append((Bucket, Key))
            return {"Body": io.BytesIO(b"payload")}

    fake_client = FakeS3Client()

    def fake_boto3_session(**kwargs):
        session_calls.append(kwargs)

        class RecordingSession:
            def get_credentials(self_inner):
                return object()

            def client(self_inner, service_name, region_name=None):
                client_calls.append((service_name, region_name))
                return fake_client

        return RecordingSession()

    monkeypatch.setattr(s3Connection.boto3, "Session", fake_boto3_session)

    content, error, status = s3Connection.download_from_s3(
        "bucket",
        "key",
        account_id=1,
        user_id=2,
        profile_name="profile",
        aws_access_key_id="AKIA123",
        aws_secret_access_key="secret456",
        aws_session_token="token789",
        region="us-west-2",
    )

    assert content == b"payload"
    assert error is None
    assert status == 200
    assert head_calls == [("bucket", "key")]
    assert get_calls == [("bucket", "key")]
    assert client_calls == [("s3", "us-west-2")]
    assert session_calls == [
        {
            "aws_access_key_id": "AKIA123",
            "aws_secret_access_key": "secret456",
            "aws_session_token": "token789",
            "region_name": "us-west-2",
        }
    ]


def test_upload_to_s3_allows_access_denied_head_bucket(monkeypatch, tmp_path):
    """Ensure uploads continue when HeadBucket lacks permission."""

    ensured: list[tuple[int, int, str]] = []

    def record_ensure(account_id, user_id, bucket):
        ensured.append((account_id, user_id, bucket))

    monkeypatch.setattr(s3Connection, "ensure_account_bucket", record_ensure)

    head_calls: list[str] = []
    upload_calls: list[tuple[str, str, str]] = []

    class FakeS3Client:
        def head_bucket(self, Bucket):
            head_calls.append(Bucket)
            raise s3Connection.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Forbidden"}},
                "HeadBucket",
            )

        def create_bucket(self, *args, **kwargs):  # pragma: no cover - safety
            raise AssertionError("Bucket creation should not be attempted")

        def upload_file(self, Filename, Bucket, Key):
            upload_calls.append((Filename, Bucket, Key))

    class FakeSession:
        def client(self, service_name, region_name=None):
            assert service_name == "s3"
            return FakeS3Client()

    file_path = tmp_path / "artifact.txt"
    file_path.write_text("payload")

    result = s3Connection.upload_to_s3(
        file_path=str(file_path),
        bucket_name="bucket",
        s3_key="key",
        account_id=123,
        user_id=456,
        profile_name=None,
        session=FakeSession(),
    )

    assert result == "key"
    assert ensured == [(123, 456, "bucket")]
    assert head_calls == ["bucket"]
    assert upload_calls == [(str(file_path), "bucket", "key")]
    assert not file_path.exists()


def test_upload_to_s3_retries_single_part_on_access_denied(monkeypatch, tmp_path):
    ensured: list[tuple[int, int, str]] = []

    def record_ensure(account_id, user_id, bucket):
        ensured.append((account_id, user_id, bucket))

    monkeypatch.setattr(s3Connection, "ensure_account_bucket", record_ensure)

    head_calls: list[str] = []

    class BaseClient:
        def head_bucket(self, Bucket):
            head_calls.append(Bucket)

        def create_bucket(self, *args, **kwargs):  # pragma: no cover - safety
            raise AssertionError("Bucket creation should not be attempted")

    class SuccessfulRetryClient(BaseClient):
        def __init__(self):
            self.upload_calls: list[tuple[str, str, str]] = []
            self.put_calls: list[tuple[str, str, bytes]] = []

        def upload_file(self, Filename, Bucket, Key):
            self.upload_calls.append((Filename, Bucket, Key))
            raise S3UploadFailedError(
                original_error=s3Connection.ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "Forbidden"}},
                    "UploadPart",
                )
            )

        def put_object(self, Bucket, Key, Body):
            payload = Body.read() if hasattr(Body, "read") else Body
            self.put_calls.append((Bucket, Key, payload))

    class FailingRetryClient(SuccessfulRetryClient):
        def put_object(self, Bucket, Key, Body):
            super().put_object(Bucket, Key, Body)
            raise s3Connection.ClientError(
                {"Error": {"Code": "InternalError", "Message": "Retry failed"}},
                "PutObject",
            )

    class FakeSession:
        def __init__(self, client):
            self._client = client

        def client(self, service_name, region_name=None):
            assert service_name == "s3"
            return self._client

    successful_file = tmp_path / "success.txt"
    successful_file.write_text("payload")

    successful_client = SuccessfulRetryClient()
    result = s3Connection.upload_to_s3(
        file_path=str(successful_file),
        bucket_name="bucket",
        s3_key="key-success",
        account_id=1,
        user_id=2,
        profile_name=None,
        session=FakeSession(successful_client),
    )

    assert result == "key-success"
    assert successful_client.upload_calls == [(str(successful_file), "bucket", "key-success")]
    assert successful_client.put_calls == [("bucket", "key-success", b"payload")]
    assert not successful_file.exists()

    failing_file = tmp_path / "failure.txt"
    failing_file.write_text("payload")

    failing_client = FailingRetryClient()
    with pytest.raises(s3Connection.ClientError):
        s3Connection.upload_to_s3(
            file_path=str(failing_file),
            bucket_name="bucket",
            s3_key="key-failure",
            account_id=3,
            user_id=4,
            profile_name=None,
            session=FakeSession(failing_client),
        )

    assert failing_client.upload_calls == [(str(failing_file), "bucket", "key-failure")]
    assert failing_client.put_calls == [("bucket", "key-failure", b"payload")]
    assert failing_file.exists()

    assert ensured == [
        (1, 2, "bucket"),
        (3, 4, "bucket"),
    ]
    assert head_calls == ["bucket", "bucket"]


def test_check_running_process_presigned_urls_use_explicit_credentials(monkeypatch):
    """Verify presigned URLs are generated after rebuilding the session."""

    account_routes = pytest.importorskip("app.accounts.routes")
    flask_app_module = pytest.importorskip("app")
    flask_app = getattr(flask_app_module, "app")

    account_details = SimpleNamespace(
        id=1,
        alias="alias",
        aws_prowler_check="completed",
        aws_prowler_compliance_report=json.dumps(
            {
                "json_report": "reports/latest.json",
                "pdf_reports": ["reports/latest.pdf"],
            }
        ),
        s3_bucket="bucket",
        access_key_id="AKIA123",
        secret_access_key="secret456",
        default_region_name="us-west-2",
        session_token="token789",
        aws_prowler_check_date_created=None,
    )

    dummy_user = SimpleNamespace(id=99, is_authenticated=True)
    monkeypatch.setattr(account_routes, "current_user", dummy_user)

    def fake_filter_by(**kwargs):
        assert kwargs == {"id": account_details.id, "account": dummy_user}
        return SimpleNamespace(first=lambda: account_details)

    AccountsStub = type("Accounts", (), {"query": SimpleNamespace(filter_by=fake_filter_by)})
    monkeypatch.setattr(account_routes, "Accounts", AccountsStub)
    monkeypatch.setattr(
        account_routes,
        "ensure_account_bucket",
        lambda *args, **kwargs: None,
    )

    monkeypatch.setattr(
        account_routes,
        "get_boto3_session",
        lambda profile_name: DummySessionWithoutCredentials(),
    )

    session_calls: list[dict] = []
    client_calls: list[tuple[str, str | None]] = []
    presigned_calls: list[tuple[str, dict, object]] = []

    class FakeS3Client:
        def generate_presigned_url(self, ClientMethod, Params, ExpiresIn=None):
            presigned_calls.append((ClientMethod, Params, ExpiresIn))
            return f"https://example.com/{Params['Key']}"

    fake_client = FakeS3Client()

    def fake_boto3_session(**kwargs):
        session_calls.append(kwargs)

        class RecordingSession:
            def get_credentials(self_inner):
                return object()

            def client(self_inner, service_name, region_name=None):
                client_calls.append((service_name, region_name))
                return fake_client

        return RecordingSession()

    monkeypatch.setattr(account_routes.boto3, "Session", fake_boto3_session)

    with flask_app.test_request_context("/check_running_process?account_id=1"):
        response = account_routes.check_running_process()

    data = response.get_json()
    assert data["status"] == "completed"
    assert data["urls"]["json_report"] == "https://example.com/reports/latest.json"
    assert data["urls"]["pdf_reports"] == [
        "https://example.com/reports/latest.pdf"
    ]

    assert presigned_calls == [
        (
            "get_object",
            {"Bucket": "bucket", "Key": "reports/latest.json"},
            None,
        ),
        (
            "get_object",
            {"Bucket": "bucket", "Key": "reports/latest.pdf"},
            None,
        ),
    ]
    assert client_calls == [("s3", "us-west-2")]
    assert session_calls == [
        {
            "aws_access_key_id": "AKIA123",
            "aws_secret_access_key": "secret456",
            "aws_session_token": "token789",
            "region_name": "us-west-2",
        }
    ]
