import secrets
import string
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from functools import lru_cache

import requests
from flask import render_template
from flask_mail import Message
from msal import ConfidentialClientApplication
from smtplib import SMTPAuthenticationError

from app import app, db, mail
from app.accounts.services import fetch_and_cache_billing_data
from app.models.models import Accounts


# Supporting Functions
@lru_cache(maxsize=128)
def get_account_details(account_alias):
    return Accounts.query.filter_by(id=account_alias).first()


def fetch_billing_data_threaded(account_details, start_date, end_date, granularity):
    with ThreadPoolExecutor() as executor:
        future = executor.submit(
            fetch_and_cache_billing_data,
            account_details.access_key_id,
            account_details.secret_access_key,
            account_details.default_region_name,
            start_date.strftime("%Y-%m-%d"),
            end_date.strftime("%Y-%m-%d"),
            granularity,
        )
        return future.result()


def fetch_billing_data_parallel(account_details, start_monthly, end_date, start_daily):
    monthly_data = fetch_and_cache_billing_data(
        account_details.access_key_id,
        account_details.secret_access_key,
        account_details.default_region_name,
        start_monthly,
        end_date,
        "MONTHLY",
    )
    daily_data = fetch_and_cache_billing_data(
        account_details.access_key_id,
        account_details.secret_access_key,
        account_details.default_region_name,
        start_daily,
        end_date,
        "DAILY",
    )
    return monthly_data, daily_data


def sort_daily_costs(daily_cost):
    """
    Sort daily costs by date.

    Args:
        daily_cost (dict): Dictionary of dates and corresponding costs.

    Returns:
        tuple: A tuple containing sorted dates and their corresponding costs.
    """
    sorted_dates = sorted(daily_cost.keys())
    sorted_costs = [daily_cost[daily_date] for daily_date in sorted_dates]
    return sorted_dates, sorted_costs


def process_billing_data(billing_data, current_month_start, current_month_end):
    """
    Process billing data into service-specific data, totals, and costs.

    Args:
        billing_data (list): List of billing records.
        current_month_start (datetime): Start of the current month.
        current_month_end (datetime): End of the current period.

    Returns:
        tuple: Processed service data, service totals, current month's cost, and daily cost.
    """
    from collections import defaultdict

    service_data = defaultdict(
        lambda: {"dates": [], "costs": [], "usage_quantities": []}
    )
    service_totals = defaultdict(float)
    current_month_cost = 0
    daily_cost = defaultdict(float)

    for record in billing_data:
        service_name = record["Service"]
        cost = float(record["Cost (USD)"])
        usage = float(record["UsageQuantity"])
        date = record["Date"]

        # Group service data
        service_data[service_name]["dates"].append(date)
        service_data[service_name]["costs"].append(cost)
        service_data[service_name]["usage_quantities"].append(usage)

        # Calculate total cost per service
        service_totals[service_name] += cost

        # Calculate current month's cost
        if (
                current_month_start.strftime("%Y-%m-%d")
                <= date
                <= current_month_end.strftime("%Y-%m-%d")
        ):
            current_month_cost += cost

        # Calculate daily cost
        daily_cost[date] += cost

    return service_data, service_totals, current_month_cost, daily_cost


def get_highest_spent_service(service_totals):
    """
    Get the service with the highest total cost.

    Args:
        service_totals (dict): Dictionary of service names and their total costs.

    Returns:
        tuple: The service name with the highest cost and its total cost.
    """
    highest_spent_service = max(service_totals, key=service_totals.get, default=None)
    highest_spent_amount = service_totals.get(highest_spent_service, 0)
    return highest_spent_service, highest_spent_amount


def get_last_month_date_range(today):
    """
    Get the start and end dates for the last month.

    Args:
        today (datetime.date): Today's date.

    Returns:
        tuple: The start and end dates for the last month in string format.
    """
    last_month_end = today.replace(day=1) - timedelta(days=1)
    last_month_start = last_month_end.replace(day=1)
    return last_month_start.strftime("%Y-%m-%d"), last_month_end.strftime("%Y-%m-%d")


def summarize_monthly_costs(monthly_data):
    """
    Summarize costs for each month.

    Args:
        monthly_data (list): List of monthly billing data.

    Returns:
        tuple: Dictionary of monthly costs, sorted months, and sorted costs.
    """
    from collections import defaultdict
    from datetime import datetime

    monthly_cost = defaultdict(float)

    for record in monthly_data:
        record_date = datetime.strptime(record["Date"], "%Y-%m-%d")
        month_year = record_date.strftime("%b %Y")
        monthly_cost[month_year] += float(record["Cost (USD)"])

    sorted_months = sorted(
        monthly_cost.keys(), key=lambda x: datetime.strptime(x, "%b %Y")
    )
    sorted_monthly_costs = [monthly_cost[month] for month in sorted_months]

    return monthly_cost, sorted_months, sorted_monthly_costs


def calculate_costs(daily_data, today, last_month_start, last_month_end):
    """
    Calculate MTD cost, forecasted cost, and last month's costs.

    Args:
        daily_data (list): List of daily billing data.
        today (datetime.date): Today's date.
        last_month_start (str): Start date of last month.
        last_month_end (str): End date of last month.

    Returns:
        tuple: MTD cost, forecasted cost, last month's total cost, and same period cost.
    """
    mtd_cost = sum(float(record["Cost (USD)"]) for record in daily_data)
    forecasted_cost = (mtd_cost / today.day) * 30

    last_month_total_cost = sum(
        float(record["Cost (USD)"])
        for record in daily_data
        if last_month_start <= record["Date"] < last_month_end
    )
    last_month_same_period_cost = sum(
        float(record["Cost (USD)"])
        for record in daily_data
        if last_month_start <= record["Date"] < last_month_end
    )

    return mtd_cost, forecasted_cost, last_month_total_cost, last_month_same_period_cost


def get_service_cost_breakdown(daily_data):
    """
    Prepare service-wise cost breakdown.

    Args:
        daily_data (list): List of daily billing data.

    Returns:
        list: List of dictionaries with service names and their costs.
    """
    from collections import defaultdict

    service_costs = defaultdict(float)
    for record in daily_data:
        service_costs[record["Service"]] += float(record["Cost (USD)"])

    return [{"name": service, "y": cost} for service, cost in service_costs.items()]




def _graph_settings():
    return {
        "client_id": app.config.get("CLIENT_ID"),
        "tenant_id": app.config.get("TENANT_ID"),
        "client_secret": app.config.get("CLIENT_SECRET"),
        "sender_email": app.config.get("SENDER_EMAIL")
        or app.config.get("MAIL_DEFAULT_SENDER")
        or app.config.get("MAIL_USERNAME"),
    }

def get_access_token():
    """Acquire an access token for Microsoft Graph API with better error handling."""

    settings = _graph_settings()
    if not all([settings["client_id"], settings["tenant_id"], settings["client_secret"]]):
        raise RuntimeError("Microsoft Graph client credentials are not fully configured.")

    # Lazily initialize the MSAL confidential client to avoid network calls during import
    app_msal = ConfidentialClientApplication(
        settings["client_id"],
        client_credential=settings["client_secret"],
        authority=f"https://login.microsoftonline.com/{settings['tenant_id']}"
    )
    try:
        token_response = app_msal.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" in token_response:
            return token_response["access_token"]
        else:
            error = token_response.get("error", "unknown_error")
            description = token_response.get("error_description", "No description available")
            app.logger.error(f"Token acquisition failed: {error} - {description}")
            raise Exception(f"Could not acquire token: {error} - {description}")
    except Exception as e:
        app.logger.error(f"Exception during token acquisition: {str(e)}")
        raise Exception(f"Token acquisition failed: {str(e)}")


def send_email_via_graph(to_email, subject, html_content):
    """Send email using Microsoft Graph API with enhanced error handling"""
    try:
        access_token = get_access_token()
        settings = _graph_settings()
        sender_email = settings["sender_email"]
        if not sender_email:
            raise RuntimeError("Microsoft Graph sender email is not configured.")

        url = f"https://graph.microsoft.com/v1.0/users/{sender_email}/sendMail"

        email_data = {
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "HTML",
                    "content": html_content
                },
                "toRecipients": [{"emailAddress": {"address": to_email}}],
                "ccRecipients": [
                    {"emailAddress": {"address": "harish.kalode@gmail.com"}},
                    {"emailAddress": {"address": "deep@gmobility.com"}}
                ]
            }
        }

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        response = requests.post(url, headers=headers, json=email_data, timeout=30)

        if response.status_code == 202:
            app.logger.info(f"Email sent successfully to {to_email}")
            return True
        else:
            error_msg = f"Graph API Error: {response.status_code} - {response.text}"
            app.logger.error(error_msg)
            raise Exception(error_msg)

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Request failed: {str(e)}")
        raise Exception(f"Email sending failed: {str(e)}")
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        raise


def send_email_via_mail_extension(
    to_email, subject, html_content, code, expiration_minutes
):
    """Send email using the configured SMTP credentials via Flask-Mail."""

    sender = (
        app.config.get("MAIL_DEFAULT_SENDER")
        or _graph_settings()["sender_email"]
        or app.config.get("MAIL_USERNAME")
    )

    if not sender:
        raise RuntimeError(
            "No sender email configured. Set MAIL_DEFAULT_SENDER, SENDER_EMAIL or MAIL_USERNAME."
        )

    plain_text_body = (
        "Hello,\n\n"
        "Use the security code below to reset your password. "
        f"It expires in {expiration_minutes} minutes.\n\n"
        f"    {code}\n\n"
        "If you did not request a reset, please contact support immediately."
    )

    message = Message(
        subject=subject,
        recipients=[to_email],
        sender=sender,
    )
    message.body = plain_text_body
    message.html = html_content

    try:
        mail.send(message)
        app.logger.info(
            "password_reset.email.smtp",
            extra={"recipient": to_email},
        )
    except SMTPAuthenticationError as exc:
        app.logger.error(
            "password_reset.email.smtp_auth_failed",
            extra={"recipient": to_email, "error": str(exc)},
        )
        raise RuntimeError(
            "SMTP authentication failed. Verify MAIL_USERNAME/MAIL_PASSWORD or configure Azure AD client credentials."
        ) from exc


def generate_reset_code(length: int = 6) -> str:
    """Generate a cryptographically secure reset code."""

    alphabet = string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def send_reset_email(user):
    """Send a password reset email with graceful transport fallbacks."""

    code = generate_reset_code()
    expiration_minutes = int(
        app.config.get("PASSWORD_RESET_CODE_EXPIRATION_MINUTES", 15)
    )

    try:
        user.set_reset_code(code, expires_in_minutes=expiration_minutes)
        db.session.flush()

        html_content = render_template(
            "reset_email.html",
            code=code,
            email=user.email,
            expiration_minutes=expiration_minutes,
        )

        graph_settings = _graph_settings()
        if all(
            [
                graph_settings["client_id"],
                graph_settings["tenant_id"],
                graph_settings["client_secret"],
            ]
        ):
            try:
                send_email_via_graph(
                    to_email=user.email,
                    subject="Reset Password",
                    html_content=html_content,
                )
            except Exception as exc:
                app.logger.warning(
                    "password_reset.email.graph_failed",
                    extra={"recipient": user.email, "error": str(exc)},
                )
                send_email_via_mail_extension(
                    to_email=user.email,
                    subject="Reset Password",
                    html_content=html_content,
                    code=code,
                    expiration_minutes=expiration_minutes,
                )
        else:
            app.logger.info(
                "password_reset.email.smtp_fallback",
                extra={"recipient": user.email},
            )
            send_email_via_mail_extension(
                to_email=user.email,
                subject="Reset Password",
                html_content=html_content,
                code=code,
                expiration_minutes=expiration_minutes,
            )
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
