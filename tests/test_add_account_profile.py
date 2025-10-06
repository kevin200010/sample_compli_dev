import os
import sys
from pathlib import Path
import subprocess

# Ensure the application uses an in-memory database and minimal config
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("FLASK_ENV", "local")
os.environ.setdefault("OPENAI_API_KEY", "test")
# Set a profile that does not exist to verify it is ignored
os.environ["AWS_PROFILE"] = "MISSING"

# Ensure project root is on the Python path so ``app`` can be imported
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.py_scripts.config import run_configure  # noqa: E402
from app.py_scripts.scrapeSecHub import run_securityhub_command, app as flask_app  # noqa: E402


def test_run_securityhub_command_ignores_aws_profile(tmp_path, monkeypatch):
    """run_securityhub_command should operate with AWS_PROFILE unset."""
    # Write findings into a temporary directory so the repo is not polluted
    monkeypatch.setattr("app.py_scripts.scrapeSecHub.app.root_path", tmp_path)

    class DummySession:
        def __init__(self, aws_access_key_id, aws_secret_access_key, region_name):
            # AWS_PROFILE should be removed before the session is created
            assert "AWS_PROFILE" not in os.environ

        def client(self, service_name):
            if service_name == "securityhub":
                class SecurityHubClient:
                    def get_findings(self, **params):
                        return {"Findings": [], "NextToken": None}
                return SecurityHubClient()
            elif service_name == "s3":
                class S3Client:
                    def upload_fileobj(self, fileobj, bucket, key):
                        pass
                return S3Client()

    monkeypatch.setattr("app.py_scripts.scrapeSecHub.boto3.Session", DummySession)

    success, _ = run_securityhub_command(
        "user@example.com",
        "alias",
        "bucket",
        "ak",
        "sk",
        "us-east-1",
    )
    assert success
    # AWS_PROFILE should be restored after the call
    assert os.environ.get("AWS_PROFILE") == "MISSING"


def test_run_configure_ignores_aws_profile(monkeypatch):
    """run_configure should execute with AWS_PROFILE removed from env."""
    calls = []

    def fake_run(cmd, check=True, env=None, capture_output=False, text=False):
        assert env is not None
        assert "AWS_PROFILE" not in env
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("app.py_scripts.config.subprocess.run", fake_run)

    success, _ = run_configure("ak", "sk", "us-east-1", "json", "alias")
    assert success
    assert len(calls) == 4
    # AWS_PROFILE remains in the process environment
    assert os.environ.get("AWS_PROFILE") == "MISSING"
