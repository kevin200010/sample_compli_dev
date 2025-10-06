"""Email helpers for password reset notifications."""

from __future__ import annotations

import logging
import os
from email.message import EmailMessage

import boto3

logger = logging.getLogger(__name__)


def send_reset_code_email(email: str, code: str) -> None:
    """Send a password reset code via SES or SMTP fallback."""

    if os.getenv("SES_FROM"):
        _send_via_ses(email, code)
    else:
        _send_via_smtp(email, code)


def _render_body(code: str) -> str:
    ttl = os.getenv("RESET_CODE_TTL_MINUTES", "15")
    return (
        "Hi,\n\n"
        "Use the code below to reset your password. It expires in "
        f"{ttl} minutes.\n\n    {code}\n\n"
        "If you did not request this reset, please contact support immediately."
    )


def _send_via_ses(email: str, code: str) -> None:
    client = boto3.client(
        "ses",
        region_name=os.getenv("AWS_REGION", "us-east-1"),
    )
    response = client.send_email(
        Source=os.environ["SES_FROM"],
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Your password reset code"},
            "Body": {"Text": {"Data": _render_body(code)}},
        },
    )
    logger.info("password_reset.email.ses", extra={"message_id": response["MessageId"]})


def _send_via_smtp(email: str, code: str) -> None:
    import smtplib

    smtp_host = os.getenv("SMTP_HOST", "localhost")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    use_tls = os.getenv("SMTP_STARTTLS", "true").lower() == "true"

    msg = EmailMessage()
    msg["Subject"] = "Your password reset code"
    msg["From"] = os.getenv("SMTP_FROM", "noreply@example.com")
    msg["To"] = email
    msg.set_content(_render_body(code))

    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
        if use_tls:
            smtp.starttls()
        if smtp_user and smtp_pass:
            smtp.login(smtp_user, smtp_pass)
        smtp.send_message(msg)
    logger.info("password_reset.email.smtp", extra={"recipient": email})
