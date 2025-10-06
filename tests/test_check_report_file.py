import json
import os
import sys
from datetime import datetime
from pathlib import Path

import pytest

try:  # pragma: no cover - fallback when botocore is unavailable
    from botocore.exceptions import ClientError
except Exception:  # pragma: no cover - executed in minimal test env
    class ClientError(Exception):
        def __init__(self, error_response=None, operation_name=None):
            super().__init__(operation_name or "ClientError")
            self.response = error_response or {}
            self.operation_name = operation_name or "client"


os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("FLASK_ENV", "local")
os.environ.setdefault("OPENAI_API_KEY", "test")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("flask")

from app import app, db  # noqa: E402
from app.models.models import Users, Accounts  # noqa: E402
from app.accounts import routes as routes_module  # noqa: E402


@pytest.fixture(autouse=True)
def app_context():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.app_context():
        db.create_all()
        yield
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client():
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def user():
    new_user = Users(
        firstname="Test",
        lastname="User",
        email="check@example.com",
        password="password",
        date_created=datetime.utcnow(),
    )
    db.session.add(new_user)
    db.session.commit()
    return new_user


@pytest.fixture
def account(user):
    acct = Accounts(
        alias="alias",
        access_key_id="AKIA",
        default_region_name="us-east-1",
        default_output_format="json",
        secret_access_key="SECRET",
        date_created=datetime.utcnow(),
        s3_bucket="bucket",
        user_id=user.id,
    )
    db.session.add(acct)
    db.session.commit()
    return acct


def _login(client, user):
    with client.session_transaction() as session:
        session["_user_id"] = user.get_id()
        session["_fresh"] = True


def test_check_report_file_uses_stored_timestamped_key(monkeypatch, client, user, account):
    stored_key = (
        f"Prowler/reports/report-2024-05-01-01-01-01/"
        f"{user.id}_{account.id}_report.ocsf.json"
    )
    account.aws_prowler_compliance_report = json.dumps({"json_report": stored_key})
    account.aws_prowler_check = "pending"
    db.session.commit()

    head_calls = []
    ensured = []

    class FakeS3Client:
        def head_object(self, Bucket, Key):
            head_calls.append((Bucket, Key))
            if Key != stored_key:
                raise ClientError({"Error": {"Code": "404"}}, "head_object")
            return {}

        def get_paginator(self, name):  # pragma: no cover - should not be used
            raise AssertionError("Paginator should not be requested when metadata is present")

    fake_client = FakeS3Client()

    class FakeSession:
        def client(self, service, region_name=None):
            assert service == "s3"
            return fake_client

    monkeypatch.setattr(routes_module, "_build_account_session", lambda *a, **k: FakeSession())
    monkeypatch.setattr(routes_module, "ensure_account_bucket", lambda *a: ensured.append(a))

    _login(client, user)

    response = client.get(f"/check_report_file/{account.id}")
    assert response.status_code == 200
    assert response.get_json() == {"exists": True}

    assert head_calls == [(account.s3_bucket, stored_key)]
    assert ensured == [(account.id, user.id, account.s3_bucket)]
    refreshed = Accounts.query.get(account.id)
    assert refreshed.aws_prowler_check == "completed"


def test_check_report_file_lists_latest_timestamp(monkeypatch, client, user, account):
    account.aws_prowler_compliance_report = ""
    account.aws_prowler_check = "pending"
    db.session.commit()

    expected_key = (
        f"Prowler/reports/report-2024-06-01-01-01-01/"
        f"{user.id}_{account.id}_report.ocsf.json"
    )
    older_key = (
        f"Prowler/reports/report-2024-05-01-01-01-01/"
        f"{user.id}_{account.id}_report.ocsf.json"
    )

    head_calls = []
    paginate_calls = []
    ensured = []

    class FakePaginator:
        def paginate(self, **kwargs):
            paginate_calls.append(kwargs)
            yield {
                "Contents": [
                    {"Key": older_key, "LastModified": datetime(2024, 5, 1, 1, 1, 1)},
                    {"Key": expected_key, "LastModified": datetime(2024, 6, 1, 1, 1, 1)},
                ]
            }

    class FakeS3Client:
        def head_object(self, Bucket, Key):
            head_calls.append((Bucket, Key))
            if Key != expected_key:
                raise ClientError({"Error": {"Code": "404"}}, "head_object")
            return {}

        def get_paginator(self, name):
            assert name == "list_objects_v2"
            return FakePaginator()

    fake_client = FakeS3Client()

    class FakeSession:
        def client(self, service, region_name=None):
            assert service == "s3"
            return fake_client

    monkeypatch.setattr(routes_module, "_build_account_session", lambda *a, **k: FakeSession())
    monkeypatch.setattr(routes_module, "ensure_account_bucket", lambda *a: ensured.append(a))

    _login(client, user)

    response = client.get(f"/check_report_file/{account.id}")
    assert response.status_code == 200
    assert response.get_json() == {"exists": True}

    assert head_calls == [(account.s3_bucket, expected_key)]
    assert paginate_calls == [
        {"Bucket": account.s3_bucket, "Prefix": "Prowler/reports/"}
    ]
    assert ensured == [(account.id, user.id, account.s3_bucket)]
    refreshed = Accounts.query.get(account.id)
    assert refreshed.aws_prowler_check == "completed"
