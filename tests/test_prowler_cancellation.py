import os
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest


os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("FLASK_ENV", "local")
os.environ.setdefault("OPENAI_API_KEY", "test")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


from app import app, db  # noqa: E402
from app.models.models import Users, Accounts  # noqa: E402
from app.accounts import routes as routes_module  # noqa: E402
from app.accounts import compliance as compliance_module  # noqa: E402
from app.accounts.compliance import ProwlerScanCancelled  # noqa: E402


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
        email="cancellation@example.com",
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


@pytest.fixture(autouse=True)
def clear_active_scans():
    with routes_module.ACTIVE_PROWLER_SCANS_LOCK:
        routes_module.ACTIVE_PROWLER_SCANS.clear()
    yield
    with routes_module.ACTIVE_PROWLER_SCANS_LOCK:
        routes_module.ACTIVE_PROWLER_SCANS.clear()


def _login(client, user):
    with client.session_transaction() as session:
        session["_user_id"] = user.get_id()
        session["_fresh"] = True


def _start_stubbed_scan(monkeypatch, account, wait_event, statuses_log=None):
    def fake_worker(
        checks,
        AWS_ACCESS_KEY,
        AWS_SECRET_KEY,
        AWS_REGION,
        AWS_ALIAS,
        user_id,
        s3_bucket,
        account_id,
        *,
        aws_session_token=None,
        cancel_event=None,
    ):
        assert cancel_event is not None
        with app.app_context():
            acct = Accounts.query.get(account_id)
            if statuses_log is not None:
                statuses_log.append(acct.aws_prowler_check)
            assert acct.aws_prowler_check == "pending"
            acct.aws_prowler_check = "running"
            acct.aws_prowler_check_date_created = datetime.utcnow()
            db.session.commit()
            if statuses_log is not None:
                statuses_log.append(acct.aws_prowler_check)

        wait_event.set()

        cancelled = cancel_event.wait(timeout=2)
        with app.app_context():
            acct = Accounts.query.get(account_id)
            if cancelled:
                final_status = "cancelled"
                acct.aws_prowler_check = final_status
                acct.aws_prowler_check_date_created = None
                acct.aws_prowler_compliance_report = None
            else:
                final_status = "completed"
                acct.aws_prowler_check = final_status
                acct.aws_prowler_check_date_created = None
            db.session.commit()
            if statuses_log is not None:
                statuses_log.append(final_status)

    monkeypatch.setattr(
        routes_module,
        "run_prowler_checks_concurrently",
        fake_worker,
    )


def test_stop_checks_cancels_active_scan(monkeypatch, client, user, account):
    _login(client, user)
    ready_event = threading.Event()
    statuses = []
    _start_stubbed_scan(monkeypatch, account, ready_event, statuses_log=statuses)

    response = client.post(f"/start_checks/{account.id}")
    assert response.status_code == 202
    assert response.get_json()["status"] == "success"

    assert ready_event.wait(timeout=2)

    with routes_module.ACTIVE_PROWLER_SCANS_LOCK:
        job = routes_module.ACTIVE_PROWLER_SCANS.get(account.id)
    assert job is not None
    assert isinstance(job.get("thread"), threading.Thread)
    assert isinstance(job.get("cancel_event"), threading.Event)

    stop_response = client.post(f"/stop_checks/{account.id}")
    assert stop_response.status_code == 200
    payload = stop_response.get_json()
    assert payload == {
        "status": "cancelled",
        "account_id": account.id,
        "running": False,
    }

    job["thread"].join(timeout=2)
    assert not job["thread"].is_alive()

    assert statuses == ["pending", "running", "cancelled"]

    with routes_module.ACTIVE_PROWLER_SCANS_LOCK:
        assert account.id not in routes_module.ACTIVE_PROWLER_SCANS

    refreshed = Accounts.query.get(account.id)
    assert refreshed.aws_prowler_check == "cancelled"
    assert refreshed.aws_prowler_compliance_report is None
    assert refreshed.aws_prowler_check_date_created is None


def test_stop_checks_clears_orphaned_pending_state(client, user, account):
    _login(client, user)

    account.aws_prowler_check = "pending"
    account.aws_prowler_check_date_created = datetime.utcnow()
    account.aws_prowler_compliance_report = "{}"
    db.session.commit()

    response = client.post(f"/stop_checks/{account.id}")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload == {
        "status": "cancelled",
        "account_id": account.id,
        "running": False,
    }

    refreshed = Accounts.query.get(account.id)
    assert refreshed.aws_prowler_check == "cancelled"
    assert refreshed.aws_prowler_check_date_created is None
    assert refreshed.aws_prowler_compliance_report is None

    status_response = client.get(f"/check_running_process?account_id={account.id}")
    assert status_response.status_code == 200
    assert status_response.get_json() == {
        "running": False,
        "status": "cancelled",
        "account_id": account.id,
    }


def test_check_running_process_reports_cancelled(monkeypatch, client, user, account):
    _login(client, user)
    ready_event = threading.Event()
    _start_stubbed_scan(monkeypatch, account, ready_event)

    start_response = client.post(f"/start_checks/{account.id}")
    assert start_response.status_code == 202
    assert ready_event.wait(timeout=2)

    with routes_module.ACTIVE_PROWLER_SCANS_LOCK:
        job = routes_module.ACTIVE_PROWLER_SCANS[account.id]

    client.post(f"/stop_checks/{account.id}")
    job["thread"].join(timeout=2)

    status_response = client.get(f"/check_running_process?account_id={account.id}")
    assert status_response.status_code == 200
    status_payload = status_response.get_json()
    assert status_payload == {
        "running": False,
        "status": "cancelled",
        "account_id": account.id,
    }


def test_start_checks_status_sequence(monkeypatch, client, user, account):
    _login(client, user)
    ready_event = threading.Event()
    statuses: list[str] = []
    _start_stubbed_scan(monkeypatch, account, ready_event, statuses_log=statuses)

    start_response = client.post(f"/start_checks/{account.id}")
    assert start_response.status_code == 202

    assert ready_event.wait(timeout=2)
    assert statuses[:2] == ["pending", "running"]

    status_response = client.get(f"/check_running_process?account_id={account.id}")
    assert status_response.status_code == 200
    payload = status_response.get_json()
    expected_start = Accounts.query.get(account.id).aws_prowler_check_date_created
    assert expected_start is not None
    assert payload == {
        "running": True,
        "status": "running",
        "account_id": account.id,
        "start_time": expected_start.isoformat(),
    }

    with routes_module.ACTIVE_PROWLER_SCANS_LOCK:
        job = routes_module.ACTIVE_PROWLER_SCANS[account.id]

    job["thread"].join(timeout=3)
    assert not job["thread"].is_alive()

    refreshed = Accounts.query.get(account.id)
    assert refreshed.aws_prowler_check == "completed"
    assert refreshed.aws_prowler_check_date_created is None
    assert statuses == ["pending", "running", "completed"]


def test_run_prowler_check_honors_cancel_event(monkeypatch):
    cancel_event = threading.Event()
    cancel_event.set()
    popen_holder: dict[str, object] = {}

    class FakePopen:
        def __init__(self, *args, **kwargs):
            popen_holder["instance"] = self
            self.returncode = 0
            self.terminate_called = False
            self.kill_called = False

        def communicate(self, timeout=None):
            if not self.terminate_called:
                raise subprocess.TimeoutExpired(cmd="prowler", timeout=timeout)
            return ("", "")

        def terminate(self):
            self.terminate_called = True

        def kill(self):
            self.kill_called = True

    monkeypatch.setattr(
        compliance_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="4.0.0", stderr="", returncode=0),
    )
    monkeypatch.setattr(compliance_module.subprocess, "Popen", FakePopen)

    with app.app_context():
        with pytest.raises(ProwlerScanCancelled):
            compliance_module.run_prowler_check(
                "check",
                "alias",
                1,
                1,
                "bucket",
                {"AWS_REGION": "us-east-1"},
                cancel_event=cancel_event,
            )

    proc = popen_holder["instance"]
    assert proc.terminate_called
    assert not proc.kill_called
