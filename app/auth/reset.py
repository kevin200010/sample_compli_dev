"""Password reset API blueprint implementing a secure email-code flow."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.exc import SQLAlchemyError

from app import db, limiter
from app.mailers.reset_email import send_reset_code_email
from app.models.models import Users
from app.security.passwords import hash_password, validate_password


bp = Blueprint("password_reset_api", __name__, url_prefix="/api/auth")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _pepper() -> str:
    pepper = current_app.config.get("RESET_CODE_PEPPER")
    if pepper:
        return pepper

    secret_key = current_app.config.get("SECRET_KEY")
    if secret_key:
        derived = hashlib.sha256(
            f"reset-pepper:{secret_key}".encode("utf-8")
        ).hexdigest()
        current_app.logger.warning(
            "RESET_CODE_PEPPER missing – derived value from SECRET_KEY for compatibility"
        )
        current_app.config["RESET_CODE_PEPPER"] = derived
        return derived

    raise RuntimeError("RESET_CODE_PEPPER is not configured")


def _email_hash(email: str) -> str:
    digest = hmac.new(_pepper().encode("utf-8"), email.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()


def _gen_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _serializer() -> URLSafeTimedSerializer:
    secret_key = current_app.config.get("SECRET_KEY")
    if not secret_key:
        raise RuntimeError("SECRET_KEY not configured")
    return URLSafeTimedSerializer(secret_key, salt="password-reset")


def _verify_reset_token(token: str, max_age: int) -> Users:
    serializer = _serializer()
    try:
        payload = serializer.loads(token, max_age=max_age)
    except SignatureExpired as exc:  # pragma: no cover - exercised via API tests
        raise ValueError("reset_token_expired") from exc
    except BadSignature as exc:
        raise ValueError("reset_token_invalid") from exc

    email = payload.get("email")
    if not email:
        raise ValueError("reset_token_invalid")

    user = Users.query.filter_by(email=email).one_or_none()
    if not user or not user.reset_token_jti:
        raise ValueError("reset_token_reused")

    token_jti = payload.get("jti") or ""
    if not hmac.compare_digest(user.reset_token_jti, token_jti):
        raise ValueError("reset_token_reused")

    issued_at = payload.get("pwd_changed_at")
    if user.password_changed_at and issued_at:
        try:
            issued_dt = datetime.fromisoformat(issued_at)
        except ValueError as exc:  # pragma: no cover - malformed payload
            raise ValueError("reset_token_invalid") from exc
        if user.password_changed_at > issued_dt:
            raise ValueError("reset_token_stale")

    return user


def _rate_limit_email_key():
    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip().lower()
    return f"reset:{email}" if email else request.remote_addr or "anonymous"


def _neutral_response():
    return jsonify({"message": "If that email exists, we’ve sent a reset code."})


@bp.route("/request-reset", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATE_LIMITS_IP", "10/hour"))
@limiter.limit(
    lambda: current_app.config.get("RATE_LIMITS_EMAIL", "5/hour"),
    key_func=_rate_limit_email_key,
)
def request_reset():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"message": "Email is required."}), 400

    user = Users.query.filter_by(email=email).one_or_none()
    code = None
    if user:
        ttl_minutes = current_app.config.get("RESET_CODE_TTL_MINUTES", 15)
        code = _gen_code()
        user.set_reset_code(code, expires_in_minutes=ttl_minutes)
        user.reset_token_jti = secrets.token_hex(16)
        try:
            db.session.commit()
        except SQLAlchemyError as exc:
            db.session.rollback()
            current_app.logger.error(
                "password_reset.request.db_error",
                extra={"email_hash": _email_hash(email), "error": str(exc)},
            )
        else:
            try:
                send_reset_code_email(email=email, code=code)
            except Exception as exc:  # pragma: no cover - depends on provider
                current_app.logger.warning(
                    "password_reset.request.email_failed",
                    extra={"email_hash": _email_hash(email), "error": str(exc)},
                )

    current_app.logger.info(
        "password_reset.request.received",
        extra={"email_hash": _email_hash(email)},
    )
    return _neutral_response()


@bp.route("/verify-reset", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATE_LIMITS_IP", "10/hour"))
@limiter.limit(
    lambda: current_app.config.get("RATE_LIMITS_EMAIL", "5/hour"),
    key_func=_rate_limit_email_key,
)
def verify_reset():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    code = (data.get("code") or "").strip()

    if not email or not code or not code.isdigit() or len(code) != 6:
        return jsonify({"message": "Invalid email or code."}), 400

    user = Users.query.filter_by(email=email).one_or_none()
    if not user or not user.reset_code_hash:
        current_app.logger.info(
            "password_reset.verify.missing",
            extra={"email_hash": _email_hash(email)},
        )
        return jsonify({"message": "Invalid code."}), 401

    max_attempts = current_app.config.get("RESET_MAX_ATTEMPTS", 5)
    if user.reset_code_attempts >= max_attempts:
        return jsonify({"message": "Too many attempts. Try again later."}), 423

    expiry = user.reset_code_expires_at
    if expiry and expiry < _now():
        user.reset_code_attempts += 1
        db.session.commit()
        return jsonify({"message": "Code expired."}), 401

    if not user.verify_reset_code(code):
        user.reset_code_attempts += 1
        db.session.commit()
        remaining = max(max_attempts - user.reset_code_attempts, 0)
        current_app.logger.info(
            "password_reset.verify.failed",
            extra={"email_hash": _email_hash(email), "remaining": remaining},
        )
        return jsonify({"message": "Invalid code."}), 401

    user.reset_code_attempts = 0
    token_ttl = current_app.config.get("RESET_TOKEN_TTL_SECONDS", 1200)
    token = user.get_reset_token(expire_sec=token_ttl)
    try:
        db.session.commit()
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.error(
            "password_reset.verify.db_error",
            extra={"email_hash": _email_hash(email), "error": str(exc)},
        )
        return jsonify({"message": "Unable to verify code right now."}), 503

    current_app.logger.info(
        "password_reset.verify.success",
        extra={"email_hash": _email_hash(email)},
    )
    return jsonify({"reset_token": token, "expires_in": token_ttl})


@bp.route("/set-password", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATE_LIMITS_IP", "30/hour"))
def set_password():
    data = request.get_json(silent=True) or {}
    token = (data.get("reset_token") or "").strip()
    new_password = (data.get("new_password") or "").strip()
    confirm_password = (data.get("confirm_password") or "").strip()

    if not token or not new_password or not confirm_password:
        return jsonify({"message": "All fields are required."}), 400

    if new_password != confirm_password:
        return jsonify({"message": "Passwords do not match."}), 400

    policy_error = validate_password(new_password)
    if policy_error:
        return jsonify({"message": policy_error}), 400

    ttl = current_app.config.get("RESET_TOKEN_TTL_SECONDS", 1200)
    try:
        user = _verify_reset_token(token, ttl)
    except ValueError as exc:
        error_map = {
            "reset_token_expired": (410, "Reset token expired."),
            "reset_token_invalid": (401, "Invalid reset token."),
            "reset_token_reused": (410, "Reset token already used."),
            "reset_token_stale": (410, "Reset token is no longer valid."),
        }
        status, message = error_map.get(str(exc), (401, "Invalid reset token."))
        return jsonify({"message": message}), status

    user.password_hash = hash_password(new_password)
    user.password_changed_at = _now()
    user.clear_reset_code()
    user.reset_token_jti = None

    try:
        db.session.commit()
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.error(
            "password_reset.set_password.db_error",
            extra={"user_id": user.id, "error": str(exc)},
        )
        return jsonify({"message": "Unable to set password right now."}), 503

    current_app.logger.info(
        "password_reset.set_password.success",
        extra={"user_id": user.id},
    )
    return jsonify({"message": "Password updated successfully."})
