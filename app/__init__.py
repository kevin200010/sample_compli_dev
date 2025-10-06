import hashlib
import os

from flask import Flask, abort, request, session
from flask_bcrypt import Bcrypt
from flask_caching import Cache
from flask_login import LoginManager, current_user
from flask_mail import Mail
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy import get_debug_queries
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import inspect, text
from openai import OpenAI
from redis import Redis
from rq import Queue

from .config import get_config

# Initialize Flask application
app = Flask(__name__, instance_relative_config=True)
app.config.from_object(get_config())


def _derive_reset_code_pepper(config):
    """Return a deterministic pepper value when one is not configured."""

    pepper = config.get("RESET_CODE_PEPPER") or os.getenv("RESET_CODE_PEPPER")
    if pepper:
        return pepper

    secret_key = config.get("SECRET_KEY") or os.getenv("SECRET_KEY")
    if not secret_key:
        return None

    derived = hashlib.sha256(
        f"reset-pepper:{secret_key}".encode("utf-8")
    ).hexdigest()
    app.logger.warning(
        "RESET_CODE_PEPPER missing – derived value from SECRET_KEY for compatibility"
    )
    return derived


app.config.setdefault("RESET_CODE_TTL_MINUTES", int(os.getenv("RESET_CODE_TTL_MINUTES", "15")))
app.config.setdefault("RESET_TOKEN_TTL_SECONDS", int(os.getenv("RESET_TOKEN_TTL_SECONDS", "1200")))
app.config.setdefault("RESET_MAX_ATTEMPTS", int(os.getenv("RESET_MAX_ATTEMPTS", "5")))
app.config.setdefault("RATE_LIMITS_IP", os.getenv("RATE_LIMITS_IP", "10/hour"))
app.config.setdefault("RATE_LIMITS_EMAIL", os.getenv("RATE_LIMITS_EMAIL", "5/hour"))
app.config.setdefault(
    "RATE_LIMIT_STORAGE_URI", os.getenv("RATE_LIMIT_STORAGE_URI", "memory://")
)
app.config.setdefault(
    "RESET_RESEND_COOLDOWN_SECONDS", int(os.getenv("RESET_RESEND_COOLDOWN_SECONDS", "60"))
)

pepper = _derive_reset_code_pepper(app.config)
if pepper:
    app.config.setdefault("RESET_CODE_PEPPER", pepper)

# Securely configure Flask app
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
cache = Cache(app)
migrate = Migrate(app, db)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=app.config["RATE_LIMIT_STORAGE_URI"],
)
limiter.init_app(app)


def ensure_s3_bucket_column():
    """Ensure the accounts table has the s3_bucket column.

    Some deployments may be missing this optional column, which results in
    runtime errors when the ORM attempts to select it. This helper checks for
    the column and creates it if necessary so the application can run without
    failing.
    """

    try:
        inspector = inspect(db.engine)
        columns = [col["name"] for col in inspector.get_columns("accounts")]
        if "s3_bucket" not in columns:
            with db.engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE accounts ADD COLUMN s3_bucket VARCHAR(80)")
                )
    except Exception as exc:
        # Log the error but continue so that application start is not blocked
        app.logger.error(f"Unable to ensure s3_bucket column exists: {exc}")


ensure_s3_bucket_column()


def ensure_reset_code_columns():
    """Ensure legacy databases have the password reset columns on users.

    The password reset flow has evolved over time and now expects several
    tracking columns to exist on the ``users`` table.  Environments that have
    not been migrated can raise MySQL 1054 errors when SQLAlchemy selects these
    fields.  To keep the application resilient we opportunistically add any
    missing columns (and their supporting index) during startup.
    """

    try:
        inspector = inspect(db.engine)
        existing_columns = {
            column_info["name"]: column_info
            for column_info in inspector.get_columns("users")
        }

        statements = []
        if "reset_code_hash" not in existing_columns:
            statements.append(
                "ALTER TABLE users ADD COLUMN reset_code_hash VARCHAR(255)"
            )
            existing_columns["reset_code_hash"] = None
        if "reset_code_expires_at" not in existing_columns:
            statements.append(
                "ALTER TABLE users ADD COLUMN reset_code_expires_at DATETIME"
            )
            existing_columns["reset_code_expires_at"] = None
        if "reset_code_attempts" not in existing_columns:
            statements.append(
                "ALTER TABLE users ADD COLUMN reset_code_attempts INT NOT NULL DEFAULT 0"
            )
            existing_columns["reset_code_attempts"] = None
        if "reset_token_jti" not in existing_columns:
            statements.append(
                "ALTER TABLE users ADD COLUMN reset_token_jti VARCHAR(64)"
            )
            existing_columns["reset_token_jti"] = None
        if "password_changed_at" not in existing_columns:
            statements.append(
                "ALTER TABLE users ADD COLUMN password_changed_at DATETIME"
            )
            existing_columns["password_changed_at"] = None

        if statements:
            with db.engine.begin() as conn:
                for statement in statements:
                    conn.execute(text(statement))

        indexes = {index["name"] for index in inspector.get_indexes("users")}
        if (
            "reset_token_jti" in existing_columns
            and "ix_users_reset_token_jti" not in indexes
        ):
            with db.engine.begin() as conn:
                conn.execute(
                    text(
                        "CREATE INDEX ix_users_reset_token_jti ON users (reset_token_jti)"
                    )
                )
    except Exception as exc:
        app.logger.error(
            f"Unable to ensure reset code columns exist on users: {exc}"
        )


ensure_reset_code_columns()


redis_conn = Redis()
q = Queue(connection=redis_conn)

# Initialize email server configuration
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "smtp.office365.com")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 587))

# Port 587 expects a STARTTLS handshake instead of implicit SSL.  Default to
# TLS for compatibility with Office365/Exchange and allow opting into SSL only
# when explicitly requested.  Prevent both options from being enabled at the
# same time to avoid the "wrong version number" SSL error observed in the
# password reset flow.
use_ssl = os.getenv("MAIL_USE_SSL")
use_tls = os.getenv("MAIL_USE_TLS")

app.config["MAIL_USE_SSL"] = (use_ssl or "False").lower() == "true"
app.config["MAIL_USE_TLS"] = (use_tls or "True").lower() == "true"

if app.config["MAIL_USE_SSL"] and app.config["MAIL_USE_TLS"]:
    # Prefer TLS because the default port uses STARTTLS.  This mirrors Flask
    # Mail's expectation that only one transport security mechanism is active
    # at a time.
    app.logger.warning(
        "Both MAIL_USE_SSL and MAIL_USE_TLS were enabled; defaulting to TLS."
    )
    app.config["MAIL_USE_SSL"] = False

app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config.setdefault(
    "MAIL_DEFAULT_SENDER",
    app.config.get("MAIL_DEFAULT_SENDER")
    or app.config.get("SENDER_EMAIL")
    or app.config.get("MAIL_USERNAME"),
)

if not app.config.get("CLIENT_SECRET"):
    app.logger.warning(
        "Microsoft Graph client secret not configured – password reset emails will use basic SMTP authentication."
    )
mail = Mail(app)

# OpenAI Client
gpt_client = OpenAI(api_key=app.config["OPENAI_API_KEY"])

# Secure session management
app.config.update(
    SESSION_COOKIE_SECURE=app.config["SESSION_COOKIE_SECURE"],
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Set the AWS profile dynamically only when explicitly configured.
# This prevents forcing a default profile that may not exist and
# ensures commands that supply their own credentials are not
# accidentally overridden.
aws_profile = app.config.get("AWS_PROFILE")
if aws_profile:
    os.environ["AWS_PROFILE"] = aws_profile
else:
    os.environ.pop("AWS_PROFILE", None)

# Initialize login manager
login_manager = LoginManager(app)
login_manager.login_view = "main.login"
login_manager.login_message_category = "info"

# Register Blueprints
from .auth_provider.routes import main as auth_blueprint
from .accounts.routes import main as account_blueprint
from .auth import reset as reset_blueprint

app.register_blueprint(auth_blueprint)
app.register_blueprint(account_blueprint)
app.register_blueprint(reset_blueprint.bp)


@app.after_request
def apply_security_headers(response):
    """Apply security headers to all responses"""
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response


@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()


@app.after_request
def log_queries(response):
    """Log slow SQL queries in development"""
    if app.config.get("ENV") == "development":
        for query in get_debug_queries():
            if query.duration > 0.5:  # Log only slow queries
                app.logger.warning(
                    f"Slow Query: {query.statement}\nDuration: {query.duration:.4f} sec"
                )
    return response


@app.before_request
def capture_ip():
    """Capture user's IP address before processing requests"""
    session["ip"] = request.remote_addr


@app.template_filter("zip")
def zip_filter(*args):
    # Use zip on multiple iterables passed to the filter
    return zip(*args)


class SecuredStaticFlask(Flask):
    """Secure static file serving for authenticated users"""

    def send_static_file(self, filename):
        if current_user.is_authenticated:
            return super(SecuredStaticFlask, self).send_static_file(filename)
        abort(403)


# Override Jinja2 options for security
app.jinja_env.autoescape = True
app.jinja_env.policies["ext.i18n"] = False  # Disable translation system if not needed

# Import CLI commands
from . import cli  # noqa: F401
