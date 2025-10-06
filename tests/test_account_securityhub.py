import os
import sys
from datetime import datetime
from pathlib import Path

import pytest
from botocore.exceptions import ClientError


os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("FLASK_ENV", "local")
os.environ.setdefault("OPENAI_API_KEY", "test")


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


from app import app, db  # noqa: E402
from app.models.models import Users, Accounts  # noqa: E402
from app.py_scripts.scrapeSecHub import run_securityhub_command  # noqa: E402


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
        email="user@example.com",
        password="password",
        date_created=datetime.utcnow(),
    )
    db.session.add(new_user)
    db.session.commit()
    return new_user


def test_run_securityhub_command_handles_disabled_security_hub(monkeypatch, tmp_path):
    """Security Hub being disabled should return a graceful notice."""

    monkeypatch.setattr("app.py_scripts.scrapeSecHub.app.root_path", tmp_path)

    class DisabledSecurityHubSession:
        def __init__(self, aws_access_key_id, aws_secret_access_key, region_name):
            pass

        def client(self, service_name):
            if service_name == "securityhub":

                class DisabledSecurityHubClient:
                    def get_findings(self, **params):
                        raise ClientError(
                            {
                                "Error": {
                                    "Code": "InvalidAccessException",
                                    "Message": "Security Hub is not enabled",
                                }
                            },
                            "GetFindings",
                        )

                return DisabledSecurityHubClient()

            class DummyS3Client:
                def upload_fileobj(self, fileobj, bucket, key):
                    raise AssertionError("S3 upload should not occur when disabled")

            return DummyS3Client()

    monkeypatch.setattr(
        "app.py_scripts.scrapeSecHub.boto3.Session", DisabledSecurityHubSession
    )

    success, message = run_securityhub_command(
        "user@example.com",
        "alias",
        "bucket",
        "ak",
        "sk",
        "us-east-1",
    )

    assert success
    assert message == "Security Hub is not enabled for this account."


def _login(client, user):
    with client.session_transaction() as session:
        session["_user_id"] = user.get_id()
        session["_fresh"] = True


def test_add_account_allows_securityhub_disabled_notice(monkeypatch, client, user):
    """Onboarding should complete when Security Hub is disabled."""

    _login(client, user)

    monkeypatch.setattr(
        "app.accounts.routes.run_configure", lambda *args, **kwargs: (True, "ok")
    )
    monkeypatch.setattr(
        "app.accounts.routes.verify_aws_profile", lambda *args, **kwargs: (True, "ok")
    )

    class DummySession:
        def __init__(self, profile_name=None, **kwargs):
            self.profile_name = profile_name

        def client(self, service_name):
            class DummyS3:
                def create_bucket(self, **kwargs):
                    return None

            return DummyS3()

    monkeypatch.setattr("app.accounts.routes.boto3.Session", DummySession)

    monkeypatch.setattr(
        "app.accounts.routes.run_securityhub_command",
        lambda *args, **kwargs: (True, "Security Hub is not enabled for this account."),
    )

    response = client.post(
        "/add-account",
        data={
            "alias": "test",
            "access_key": "AKIA",
            "secret_key": "SECRET",
            "default_region": "us-east-1",
        },
    )

    assert response.status_code == 302
    assert Accounts.query.count() == 1
    with client.session_transaction() as session:
        flashes = session.get("_flashes", [])
    assert ("info", "Security Hub is not enabled for this account.") in flashes
    success_flash_messages = [msg for category, msg in flashes if category == "success"]
    assert success_flash_messages == ["Account added successfully."]


def test_add_account_blocks_on_securityhub_error(monkeypatch, client, user):
    """Other Security Hub ClientErrors should stop onboarding."""

    _login(client, user)

    monkeypatch.setattr(
        "app.accounts.routes.run_configure", lambda *args, **kwargs: (True, "ok")
    )
    monkeypatch.setattr(
        "app.accounts.routes.verify_aws_profile", lambda *args, **kwargs: (True, "ok")
    )

    class DummySession:
        def __init__(self, profile_name=None, **kwargs):
            self.profile_name = profile_name

        def client(self, service_name):
            class DummyS3:
                def create_bucket(self, **kwargs):
                    return None

            return DummyS3()

    monkeypatch.setattr("app.accounts.routes.boto3.Session", DummySession)

    monkeypatch.setattr(
        "app.accounts.routes.run_securityhub_command",
        lambda *args, **kwargs: (False, "Access denied. Ensure your IAM role has the required permissions."),
    )

    response = client.post(
        "/add-account",
        data={
            "alias": "test",
            "access_key": "AKIA",
            "secret_key": "SECRET",
            "default_region": "us-east-1",
        },
    )

    assert response.status_code == 302
    assert Accounts.query.count() == 0
    with client.session_transaction() as session:
        flashes = session.get("_flashes", [])
    assert ("error", "Access denied. Ensure your IAM role has the required permissions.") in flashes
