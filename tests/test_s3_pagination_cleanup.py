import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

from datetime import datetime as real_datetime

try:  # pragma: no cover - runtime dependency shim for tests
    import boto3  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback when boto3 absent
    boto3 = ModuleType("boto3")

    class _StubSession:  # noqa: D401 - simple stub for tests
        """Stub Session that will be patched by tests."""

        def __init__(self, *args, **kwargs):
            pass

        def client(self, service):  # pragma: no cover - should be monkeypatched
            raise NotImplementedError

    boto3.Session = _StubSession  # type: ignore[attr-defined]
    sys.modules.setdefault("boto3", boto3)

try:  # pragma: no cover - runtime dependency shim for tests
    from botocore.exceptions import ClientError  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback when botocore absent
    botocore_module = ModuleType("botocore")
    exceptions_module = ModuleType("botocore.exceptions")

    class ClientError(Exception):
        def __init__(self, error_response, operation_name):
            super().__init__(error_response.get("Error", {}).get("Message", ""))
            self.response = error_response
            self.operation_name = operation_name

    exceptions_module.ClientError = ClientError  # type: ignore[attr-defined]
    botocore_module.exceptions = exceptions_module  # type: ignore[attr-defined]
    sys.modules.setdefault("botocore", botocore_module)
    sys.modules.setdefault("botocore.exceptions", exceptions_module)


class _DummyLogger:
    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


class _DummySession:
    def commit(self):
        pass

    def remove(self):
        pass


class _DummyDB:
    def __init__(self):
        self.session = _DummySession()


flask_module = sys.modules.setdefault("flask", ModuleType("flask"))


class _DummyApp:
    def __init__(self):
        self.logger = _DummyLogger()
        self.config = {}
        self.root_path = str(Path(__file__).resolve().parents[1] / "app")
        self.jinja_env = SimpleNamespace(autoescape=False, policies={})

    def app_context(self):
        app_ref = self

        class _Ctx:
            def __enter__(self_inner):
                flask_module.current_app = app_ref
                return app_ref

            def __exit__(self_inner, exc_type, exc, tb):
                return False

        return _Ctx()

    def register_blueprint(self, *args, **kwargs):
        return None

    def after_request(self, func):
        return func

    def teardown_appcontext(self, func):
        return func

    def before_request(self, func):
        return func

    def template_filter(self, name):
        def decorator(func):
            return func

        return decorator


dummy_app = _DummyApp()
flask_module.current_app = dummy_app
flask_module.request = SimpleNamespace(args={}, remote_addr="0.0.0.0")
flask_module.session = {}
flask_module.Blueprint = lambda *a, **k: None
flask_module.abort = RuntimeError

app_module = ModuleType("app")
app_module.__path__ = [str(Path(__file__).resolve().parents[1] / "app")]
app_module.app = dummy_app
app_module.db = _DummyDB()
sys.modules["app"] = app_module

accounts_package = ModuleType("app.accounts")
accounts_package.__path__ = [str(Path(__file__).resolve().parents[1] / "app/accounts")]
sys.modules["app.accounts"] = accounts_package

helpers_module = ModuleType("app.accounts.helpers")
helpers_module.ensure_account_bucket = lambda *a, **k: None
sys.modules["app.accounts.helpers"] = helpers_module

py_scripts_package = ModuleType("app.py_scripts")
py_scripts_package.__path__ = [str(Path(__file__).resolve().parents[1] / "app/py_scripts")]
sys.modules["app.py_scripts"] = py_scripts_package

s3_module = ModuleType("app.py_scripts.s3Connection")
s3_module.upload_to_s3 = lambda *a, **k: ""
sys.modules["app.py_scripts.s3Connection"] = s3_module

models_package = ModuleType("app.models")
models_package.__path__ = [str(Path(__file__).resolve().parents[1] / "app/models")]
sys.modules["app.models"] = models_package

models_module = ModuleType("app.models.models")
models_module.Accounts = type("Accounts", (), {"query": MagicMock()})
sys.modules["app.models.models"] = models_module

matplotlib_module = sys.modules.setdefault("matplotlib", ModuleType("matplotlib"))
matplotlib_module.use = lambda *a, **k: None

plt_module = sys.modules.setdefault("matplotlib.pyplot", ModuleType("matplotlib.pyplot"))
plt_module.figure = lambda *a, **k: None
plt_module.pie = lambda *a, **k: None
plt_module.savefig = lambda *a, **k: None
plt_module.close = lambda *a, **k: None

reportlab_module = sys.modules.setdefault("reportlab", ModuleType("reportlab"))
lib_module = sys.modules.setdefault("reportlab.lib", ModuleType("reportlab.lib"))
colors_module = sys.modules.setdefault("reportlab.lib.colors", ModuleType("reportlab.lib.colors"))
colors_module.HexColor = lambda *a, **k: None
colors_module.black = None

pagesizes_module = sys.modules.setdefault(
    "reportlab.lib.pagesizes", ModuleType("reportlab.lib.pagesizes")
)
pagesizes_module.letter = None

pdfgen_module = sys.modules.setdefault("reportlab.pdfgen", ModuleType("reportlab.pdfgen"))
canvas_module = sys.modules.setdefault(
    "reportlab.pdfgen.canvas", ModuleType("reportlab.pdfgen.canvas")
)


class _DummyCanvas:
    def __init__(self, *args, **kwargs):
        pass

    def setFont(self, *args, **kwargs):
        pass

    def setFillColor(self, *args, **kwargs):
        pass

    def drawString(self, *args, **kwargs):
        pass

    def drawCentredString(self, *args, **kwargs):
        pass

    def drawRightString(self, *args, **kwargs):
        pass

    def line(self, *args, **kwargs):
        pass

    def rect(self, *args, **kwargs):
        pass

    def drawImage(self, *args, **kwargs):
        pass

    def save(self):
        pass


canvas_module.Canvas = _DummyCanvas

platypus_module = sys.modules.setdefault(
    "reportlab.platypus", ModuleType("reportlab.platypus")
)
platypus_module.Table = lambda *a, **k: SimpleNamespace(setStyle=lambda *a, **k: None)
platypus_module.TableStyle = lambda *a, **k: None

# Use in-memory database and avoid network connections on import
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("FLASK_ENV", "local")
os.environ.setdefault("OPENAI_API_KEY", "test")

# Ensure project root is on the Python path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import importlib

compliance = importlib.import_module("app.accounts.compliance")  # noqa: E402
run_prowler_checks_concurrently = compliance.run_prowler_checks_concurrently


def test_timestamped_prefix_uploaded_without_cleanup(tmp_path, monkeypatch):
    """Reports are stored under a timestamped prefix without deleting objects."""

    report = tmp_path / "report.json"
    report.write_text("[]")

    class FixedDateTime:
        @classmethod
        def utcnow(cls):
            return real_datetime(2023, 1, 2, 3, 4, 5)

        @classmethod
        def now(cls, tz=None):  # pragma: no cover - maintain interface
            return real_datetime(2023, 1, 2, 3, 4, 5)

    class FakeS3Client:
        def __init__(self):
            self.list_calls = 0
            self.delete_calls = 0

        def list_objects_v2(self, *args, **kwargs):
            self.list_calls += 1
            return {"Contents": []}

        def delete_objects(self, *args, **kwargs):
            self.delete_calls += 1
            return {"Deleted": []}

        def generate_presigned_url(self, ClientMethod, Params, ExpiresIn=None):
            return "https://example.com"

    fake_client = FakeS3Client()

    session_calls: list[dict] = []

    class FakeSession:
        def __init__(self, **kwargs):
            session_calls.append(kwargs)

        def client(self, service):
            assert service == "s3"
            return fake_client

    monkeypatch.setattr(compliance.boto3, "Session", FakeSession)

    upload_keys: list[str] = []

    def fake_upload_to_s3(file_path, bucket_name, s3_key, *args, **kwargs):
        upload_keys.append(s3_key)
        return s3_key

    monkeypatch.setattr(compliance, "upload_to_s3", fake_upload_to_s3)
    monkeypatch.setattr(compliance, "datetime", FixedDateTime)
    def fake_run_prowler_check(*args, **kwargs):
        env = kwargs.get("env") or args[-1]
        assert env.get("AWS_SESSION_TOKEN") == "session-token"
        return str(report), 0

    monkeypatch.setattr(
        compliance,
        "run_prowler_check",
        fake_run_prowler_check,
    )

    def fake_generate_reports(*args, **kwargs):
        storage_prefix = kwargs.get("storage_prefix")
        assert storage_prefix and storage_prefix.endswith("/")
        return [], [str(tmp_path / "dummy.pdf")]

    monkeypatch.setattr(compliance, "generate_reports", fake_generate_reports)
    monkeypatch.setattr(
        compliance, "ensure_account_bucket", lambda *a, **k: None
    )

    account = type("Account", (), {})()
    account.aws_prowler_check = ""
    account.aws_prowler_check_date_created = None
    account.aws_prowler_compliance_report = ""

    query_mock = MagicMock()
    query_mock.get.return_value = account
    monkeypatch.setattr(
        compliance, "Accounts", type("Accounts", (), {"query": query_mock})
    )
    monkeypatch.setattr(compliance.db.session, "commit", lambda: None)

    run_prowler_checks_concurrently(
        [],
        "access",
        "secret",
        "us-east-1",
        "alias",
        user_id=1,
        s3_bucket="bucket",
        account_id=1,
        aws_session_token="session-token",
    )

    expected_prefix = "Prowler/reports/report-2023-01-02-03-04-05/"
    assert all(key.startswith(expected_prefix) for key in upload_keys)
    assert fake_client.list_calls == 0
    assert fake_client.delete_calls == 0
    assert session_calls == [
        {
            "aws_access_key_id": "access",
            "aws_secret_access_key": "secret",
            "region_name": "us-east-1",
            "aws_session_token": "session-token",
        }
    ]


def test_access_denied_marks_failure(tmp_path, monkeypatch):
    """AccessDenied errors during upload update the account state to failed."""

    report = tmp_path / "report.json"
    report.write_text("[]")

    class UploadDeniedClient:
        def generate_presigned_url(self, ClientMethod, Params, ExpiresIn=None):
            return "https://example.com"

    def failing_upload(*args, **kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "PutObject",
        )

    session_calls: list[dict] = []

    class FakeDeniedSession:
        def __init__(self, **kwargs):
            session_calls.append(kwargs)

        def client(self, service):
            assert service == "s3"
            return UploadDeniedClient()

    monkeypatch.setattr(compliance.boto3, "Session", FakeDeniedSession)
    monkeypatch.setattr(compliance, "upload_to_s3", failing_upload)
    def fake_run_prowler_check(*args, **kwargs):
        env = kwargs.get("env") or args[-1]
        assert env.get("AWS_SESSION_TOKEN") == "session-token"
        return str(report), 0

    monkeypatch.setattr(
        compliance,
        "run_prowler_check",
        fake_run_prowler_check,
    )
    monkeypatch.setattr(
        compliance,
        "generate_reports",
        lambda *a, **k: ([], [str(tmp_path / "dummy.pdf")]),
    )
    monkeypatch.setattr(
        compliance, "ensure_account_bucket", lambda *a, **k: None
    )

    account = type("Account", (), {})()
    account.aws_prowler_check = ""
    account.aws_prowler_check_date_created = None
    account.aws_prowler_compliance_report = ""

    query_mock = MagicMock()
    query_mock.get.return_value = account
    monkeypatch.setattr(
        compliance, "Accounts", type("Accounts", (), {"query": query_mock})
    )

    commit_calls = []

    def fake_commit():
        commit_calls.append(object())

    monkeypatch.setattr(compliance.db.session, "commit", fake_commit)

    run_prowler_checks_concurrently(
        [],
        "access",
        "secret",
        "us-east-1",
        "alias",
        user_id=1,
        s3_bucket="bucket",
        account_id=1,
        aws_session_token="session-token",
    )

    assert account.aws_prowler_check == "failed"
    assert account.aws_prowler_check_date_created is None
    assert "denied" in account.aws_prowler_compliance_report.lower()
    # ``check_running_process`` filters out accounts not marked as pending/running
    assert account.aws_prowler_check not in ("pending", "running")
    # One commit for marking running, one for failure update
    assert len(commit_calls) >= 2
    assert session_calls == [
        {
            "aws_access_key_id": "access",
            "aws_secret_access_key": "secret",
            "region_name": "us-east-1",
            "aws_session_token": "session-token",
        }
    ]
