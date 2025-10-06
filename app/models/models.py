import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer
from itsdangerous.exc import BadSignature, SignatureExpired

from app import app, bcrypt, db, login_manager


# Job status options for long running tasks such as Prowler checks
JOB_STATUS_OPTIONS = ("pending", "running", "completed", "failed")


# user loader to load user to login
@login_manager.user_loader
def load_user(user_email):
    """Required for session management in Flask-Login requirement, We are storing emails of every user in session to
    satisfy session management unique identity. Because email is an unique identity in our system for every user we
    are using it. Make sure we should add email validation in all the registration form's in case if we add another
    user, and add the same user login identity in load_user too."""
    return Users.query.filter_by(email=user_email).first()


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(120), nullable=False)
    lastname = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password = db.Column(db.String(150), nullable=False)
    date_created = db.Column(db.DateTime, nullable=False)
    users_accounts = db.relationship("Accounts", backref="account", lazy=True)
    reset_code_hash = db.Column(db.String(255), nullable=True)
    reset_code_expires_at = db.Column(db.DateTime, nullable=True)
    reset_code_attempts = db.Column(db.Integer, nullable=False, default=0)
    reset_token_jti = db.Column(db.String(64), nullable=True, index=True)
    password_changed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    """LOGIN REQUIREMENT FUNCTION"""

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.email

    def _reset_serializer(self) -> URLSafeTimedSerializer:
        secret_key = app.config.get("SECRET_KEY")
        if not secret_key:
            raise RuntimeError("SECRET_KEY is not configured")
        return URLSafeTimedSerializer(secret_key, salt="password-reset")

    def get_reset_token(self, expire_sec: int = 1800) -> str:
        """Generate a signed reset token and persist a new JTI."""

        serializer = self._reset_serializer()
        jti = secrets.token_hex(16)
        self.reset_token_jti = jti
        payload = {
            "email": self.email,
            "jti": jti,
            "pwd_changed_at": (
                self.password_changed_at.isoformat()
                if self.password_changed_at
                else None
            ),
        }
        token = serializer.dumps(payload)
        # ``expire_sec`` is returned for compatibility with legacy callers.
        return token

    @staticmethod
    def verify_reset_token(token: str, expire_sec: int = 1800):
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="password-reset")
        try:
            payload = serializer.loads(token, max_age=expire_sec)
        except SignatureExpired as exc:
            raise exc
        except BadSignature:
            return None
        except Exception as exc:  # pragma: no cover - defensive logging
            app.logger.warning(f"Unexpected error validating reset token: {exc}")
            return None

        email = payload.get("email")
        if not email:
            return None

        user = Users.query.filter_by(email=email).first()
        if not user or not user.reset_token_jti:
            return None
        if not hmac.compare_digest(user.reset_token_jti, payload.get("jti", "")):
            return None

        issued_at = payload.get("pwd_changed_at")
        if user.password_changed_at and issued_at:
            try:
                issued_dt = datetime.fromisoformat(issued_at)
            except ValueError:  # pragma: no cover - defensive fallback
                return None
            if user.password_changed_at > issued_dt:
                return None
        return user

    @property
    def password_hash(self) -> str:
        return self.password

    @password_hash.setter
    def password_hash(self, value: str) -> None:
        self.password = value

    def _pepper(self) -> str:
        pepper = app.config.get("RESET_CODE_PEPPER") or os.getenv("RESET_CODE_PEPPER")
        if not pepper:
            raise RuntimeError("RESET_CODE_PEPPER is not configured")
        return pepper

    def set_reset_code(self, code: str, expires_in_minutes: int = 15) -> None:
        """Hash and store a reset code along with its expiry."""

        if not code:
            self.clear_reset_code()
            return

        digest = hashlib.sha256()
        digest.update(code.encode("utf-8"))
        digest.update(self._pepper().encode("utf-8"))
        digest.update(self.email.lower().encode("utf-8"))
        self.reset_code_hash = digest.hexdigest()
        expires_delta = timedelta(minutes=expires_in_minutes)
        self.reset_code_expires_at = datetime.now(timezone.utc) + expires_delta
        self.reset_code_attempts = 0

    def verify_reset_code(self, code: str) -> bool:
        """Check a provided code against the stored hash and expiry."""

        if not self.reset_code_hash or not self.reset_code_expires_at:
            return False
        expiry = self.reset_code_expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expiry:
            return False
        digest = hashlib.sha256()
        digest.update(code.encode("utf-8"))
        digest.update(self._pepper().encode("utf-8"))
        digest.update(self.email.lower().encode("utf-8"))
        expected = digest.hexdigest()
        return hmac.compare_digest(self.reset_code_hash, expected)

    def clear_reset_code(self) -> None:
        """Remove any stored reset code information."""

        self.reset_code_hash = None
        self.reset_code_expires_at = None
        self.reset_code_attempts = 0


class Accounts(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    alias = db.Column(db.String(80), nullable=False)
    access_key_id = db.Column(db.String(80), nullable=False)
    default_region_name = db.Column(db.String(80), nullable=False)
    default_output_format = db.Column(db.String(80), nullable=False)
    secret_access_key = db.Column(db.String(150), nullable=False)
    date_created = db.Column(db.DateTime, nullable=False)
    aws_prowler_check_date_created = db.Column(db.DateTime, nullable=True)
    aws_prowler_check = db.Column(db.String(80), nullable=True)
    aws_prowler_compliance_report = db.Column(db.Text, nullable=True)
    s3_bucket = db.Column(db.String(80), nullable=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
