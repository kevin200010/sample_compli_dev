import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest


# Provide lightweight shims so the application code can be imported without
# installing third-party dependencies in the execution environment used for
# tests.
app_module = ModuleType("app")


class _DummyLogger:
    def warning(self, *args, **kwargs):  # pragma: no cover - logging stub
        pass

    def info(self, *args, **kwargs):  # pragma: no cover - logging stub
        pass

    def error(self, *args, **kwargs):  # pragma: no cover - logging stub
        pass


class _DummyApp:
    def __init__(self):
        self.config = {
            "SECRET_KEY": "testing-secret",
            "RESET_CODE_PEPPER": "unit-test-pepper",
        }
        self.logger = _DummyLogger()


class _DummyLoginManager:
    def user_loader(self, func):  # pragma: no cover - decorator stub
        return func


class _DummyHash:
    def __init__(self, value):
        self.value = value

    def decode(self, _):  # pragma: no cover - decode shim
        return self.value


class _DummyBcrypt:
    def generate_password_hash(self, value):
        return _DummyHash(value)

    @staticmethod
    def check_password_hash(stored, candidate):
        return stored == candidate


class _DummyLimiter:
    def limit(self, *args, **kwargs):  # pragma: no cover - decorator stub
        def decorator(func):
            return func

        return decorator


class _DummyDB:
    class Model:  # pragma: no cover - simple ORM base stub
        pass

    def Column(self, *args, **kwargs):
        return None

    def String(self, *args, **kwargs):
        return None

    def Integer(self, *args, **kwargs):
        return None

    def DateTime(self, *args, **kwargs):
        return None

    def Text(self, *args, **kwargs):
        return None

    def ForeignKey(self, *args, **kwargs):
        return None

    def relationship(self, *args, **kwargs):
        return None


app_module.db = _DummyDB()
app_module.login_manager = _DummyLoginManager()
app_module.app = _DummyApp()
app_module.bcrypt = _DummyBcrypt()
app_module.limiter = _DummyLimiter()
app_module.__path__ = [str(ROOT / "app")]

sys.modules.setdefault("app", app_module)


flask_login_module = ModuleType("flask_login")


class UserMixin:  # pragma: no cover - mixin stub for tests
    pass


flask_login_module.UserMixin = UserMixin
sys.modules.setdefault("flask_login", flask_login_module)


# Minimal ``flask`` shim providing objects used during imports.
flask_module = ModuleType("flask")


class _DummyBlueprint:
    def __init__(self, *args, **kwargs):  # pragma: no cover - blueprint stub
        pass

    def route(self, *args, **kwargs):  # pragma: no cover - decorator stub
        def decorator(func):
            return func

        return decorator


class _DummyRequest:
    remote_addr = "127.0.0.1"

    @staticmethod
    def get_json(silent=False):  # pragma: no cover - request stub
        return {}


flask_module.Blueprint = _DummyBlueprint
flask_module.current_app = app_module.app
flask_module.jsonify = lambda data: data  # pragma: no cover - jsonify stub
flask_module.request = _DummyRequest()

sys.modules.setdefault("flask", flask_module)


# Minimal ``sqlalchemy.exc`` shim for tests.
sqlalchemy_module = ModuleType("sqlalchemy")
sqlalchemy_exc_module = ModuleType("sqlalchemy.exc")


class SQLAlchemyError(Exception):  # pragma: no cover - simple exception stub
    pass


sqlalchemy_exc_module.SQLAlchemyError = SQLAlchemyError
sys.modules.setdefault("sqlalchemy", sqlalchemy_module)
sys.modules.setdefault("sqlalchemy.exc", sqlalchemy_exc_module)


# Minimal ``boto3`` shim for email helper imports.
boto3_module = ModuleType("boto3")


class _DummySESClient:  # pragma: no cover - boto3 SES stub
    def send_email(self, **kwargs):
        return {"MessageId": "stub"}


def _dummy_client(*args, **kwargs):  # pragma: no cover - boto3 client factory
    return _DummySESClient()


boto3_module.client = _dummy_client
sys.modules.setdefault("boto3", boto3_module)


# Minimal ``argon2`` shim for password helpers used in imports.
argon2_module = ModuleType("argon2")


class PasswordHasher:  # pragma: no cover - argon2 stub
    def __init__(self, *args, **kwargs):
        pass

    def hash(self, value):
        return f"argon2:{value}"

    @staticmethod
    def verify(hashed, value):
        return hashed == f"argon2:{value}"


argon2_module.PasswordHasher = PasswordHasher
argon2_exceptions_module = ModuleType("argon2.exceptions")


class VerifyMismatchError(Exception):  # pragma: no cover - argon2 stub
    pass


argon2_exceptions_module.VerifyMismatchError = VerifyMismatchError
argon2_module.exceptions = argon2_exceptions_module
sys.modules.setdefault("argon2", argon2_module)
sys.modules.setdefault("argon2.exceptions", argon2_exceptions_module)


# itsdangerous shim providing the serializer and exceptions used in tests.
itsdangerous_module = ModuleType("itsdangerous")
itsdangerous_exc_module = ModuleType("itsdangerous.exc")


class BadSignature(Exception):
    """Exception raised when token validation fails."""


class SignatureExpired(BadSignature):
    """Exception raised when a token has expired."""


class TimedJSONWebSignatureSerializer:
    """Minimal serializer supporting ``dumps`` and ``loads`` with expiry."""

    def __init__(self, secret_key, expires_in=None, salt=None):
        self.secret_key = secret_key
        self.expires_in = expires_in
        self.salt = salt

    def dumps(self, data):
        payload = {
            "data": data,
            "timestamp": time.time(),
            "expires_in": self.expires_in,
        }
        return json.dumps(payload).encode("utf-8")

    def loads(self, token, max_age=None):
        if isinstance(token, bytes):  # pragma: no cover - defensive branch
            token = token.decode("utf-8")

        try:
            payload = json.loads(token)
        except Exception as exc:  # pragma: no cover - defensive
            raise BadSignature(str(exc)) from exc

        expires_in = max_age if max_age is not None else payload.get("expires_in")
        if expires_in is not None:
            age = time.time() - payload["timestamp"]
            if age > expires_in:
                raise SignatureExpired("Token expired")

        return payload["data"]


class URLSafeTimedSerializer(TimedJSONWebSignatureSerializer):
    pass


itsdangerous_module.TimedJSONWebSignatureSerializer = TimedJSONWebSignatureSerializer
itsdangerous_module.URLSafeTimedSerializer = URLSafeTimedSerializer
itsdangerous_module.exc = itsdangerous_exc_module
itsdangerous_module.BadSignature = BadSignature
itsdangerous_module.SignatureExpired = SignatureExpired
itsdangerous_exc_module.BadSignature = BadSignature
itsdangerous_exc_module.SignatureExpired = SignatureExpired

sys.modules.setdefault("itsdangerous", itsdangerous_module)
sys.modules.setdefault("itsdangerous.exc", itsdangerous_exc_module)


# Ensure deterministic configuration for the application during tests.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("FLASK_ENV", "local")
os.environ.setdefault("OPENAI_API_KEY", "test")
os.environ.setdefault("RESET_CODE_PEPPER", "unit-test-pepper")


from app.models.models import Users  # noqa: E402  # pylint: disable=wrong-import-position


class DummyQuery:
    """Simple stand-in for ``Users.query`` used in tests."""

    def __init__(self, expected_email, result):
        self.expected_email = expected_email
        self._result = result
        self.filter_args = None

    def filter_by(self, **kwargs):
        self.filter_args = kwargs
        assert kwargs == {"email": self.expected_email}
        return self

    def first(self):
        return self._result


def _make_user(email="user@example.com"):
    user = Users()
    user.email = email
    return user


def test_pepper_derives_from_secret_key(monkeypatch):
    from app.auth import reset

    dummy_logger = SimpleNamespace(warning=lambda *args, **kwargs: None)
    dummy_app = SimpleNamespace(config={"SECRET_KEY": "derived-secret"}, logger=dummy_logger)
    monkeypatch.setattr(reset, "current_app", dummy_app)

    pepper = reset._pepper()

    expected = hashlib.sha256(
        b"reset-pepper:derived-secret"
    ).hexdigest()
    assert pepper == expected
    assert dummy_app.config["RESET_CODE_PEPPER"] == expected


def test_verify_reset_token_returns_user(monkeypatch):
    user = _make_user()
    token = user.get_reset_token(expire_sec=30)

    dummy_query = DummyQuery(user.email, user)
    monkeypatch.setattr(Users, "query", dummy_query, raising=False)

    assert Users.verify_reset_token(token, expire_sec=30) is user
    assert dummy_query.filter_args == {"email": user.email}


def test_verify_reset_token_expired(monkeypatch):
    user = _make_user("expired@example.com")
    token = user.get_reset_token(expire_sec=1)

    dummy_query = DummyQuery(user.email, user)
    monkeypatch.setattr(Users, "query", dummy_query, raising=False)

    original_time = time.time

    def future_time():
        return original_time() + 5

    monkeypatch.setattr(time, "time", future_time)

    with pytest.raises(SignatureExpired):
        Users.verify_reset_token(token, expire_sec=1)


def test_verify_reset_token_invalid(monkeypatch):
    dummy_query = DummyQuery("unused@example.com", None)
    monkeypatch.setattr(Users, "query", dummy_query, raising=False)

    assert Users.verify_reset_token("invalid-token") is None
    assert dummy_query.filter_args is None


def test_verify_reset_token_rejects_reused(monkeypatch):
    user = _make_user()
    token = user.get_reset_token(expire_sec=60)

    dummy_query = DummyQuery(user.email, user)
    monkeypatch.setattr(Users, "query", dummy_query, raising=False)

    user.reset_token_jti = "different"

    assert Users.verify_reset_token(token, expire_sec=60) is None


def test_set_reset_code_and_verify_success():
    user = _make_user()
    user.set_reset_code("123456", expires_in_minutes=1)

    assert user.reset_code_hash != "123456"
    assert user.reset_code_expires_at is not None
    assert user.verify_reset_code("123456")


def test_verify_reset_code_invalid_when_expired():
    user = _make_user()
    user.set_reset_code("654321", expires_in_minutes=1)
    user.reset_code_expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)

    assert not user.verify_reset_code("654321")


def test_clear_reset_code_removes_hash_and_expiry():
    user = _make_user()
    user.set_reset_code("111111", expires_in_minutes=1)
    user.clear_reset_code()

    assert user.reset_code_hash is None
    assert user.reset_code_expires_at is None
    assert user.reset_code_attempts == 0
