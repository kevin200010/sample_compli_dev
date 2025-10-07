import base64
import csv
import hashlib
import io
import json
import os
import shlex
import subprocess
import threading
import traceback
from typing import Any
from collections import defaultdict
from datetime import date, datetime, timedelta

import boto3
import uuid
import markdown2
from botocore.exceptions import ClientError
from flask import (
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
    current_app,
)
from flask_login import current_user, login_required
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from app.py_scripts.compliance import generate_pdf_report
from app.py_scripts.config import run_configure, verify_aws_profile
from app.py_scripts.extractCommands import extract_aws_cli_commands
from app.py_scripts.hipaa import (
    generate_hipaa_report,
    get_remediation_steps,
    perform_compliance_checks,
    get_section_explanation,
)
from app.py_scripts.aws_session import get_boto3_session
from app.py_scripts.s3Connection import download_from_s3
from app.accounts.helpers import ensure_account_bucket
from app.py_scripts.scrapeSecHub import run_securityhub_command
from . import main
from .nova_sonic import build_nova_sonic_context
from .compliance import (
    run_prowler_checks_concurrently,
    generate_reports_data,
    S3_REPORT_PREFIX,
)
from .forms.forms import AddAccountForm
from .services import (
    pop_session_if_already_exist,
    fetch_and_cache_billing_data,
    compliance_logo_links,
)
from .. import db, cache, app, gpt_client
from ..models.models import Accounts
from ..py_scripts.removeAccount import remove_account


ACTIVE_PROWLER_SCANS: dict[int, dict[str, Any]] = {}
ACTIVE_PROWLER_SCANS_LOCK = threading.Lock()


def _extract_account_credentials(account_details: Accounts) -> tuple[str | None, str | None, str | None, str | None]:
    """Return the stored AWS credentials for *account_details*."""

    session_token = getattr(account_details, "session_token", None)
    if session_token is None:
        session_token = getattr(account_details, "aws_session_token", None)

    return (
        getattr(account_details, "access_key_id", None),
        getattr(account_details, "secret_access_key", None),
        session_token,
        getattr(account_details, "default_region_name", None),
    )


def _build_account_session(
    profile_name: str,
    access_key_id: str | None,
    secret_access_key: str | None,
    region_name: str | None,
    session_token: str | None,
):
    """Return a :class:`boto3.Session` using stored credentials when needed."""

    if access_key_id and secret_access_key:
        return boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            aws_session_token=session_token,
            region_name=region_name,
        )

    return get_boto3_session(profile_name)


@main.route("/Compliance-Checks", methods=["POST", "GET"])
@login_required
def compliance_check():
    """
    Handles service information page rendering.
    Uses session management to track the selected AWS account.
    """
    pop_session_if_already_exist()

    account_alias = session.get("selected_account")
    if not account_alias:
        flash("No account selected. Please select an account first.", "error")
        return redirect(
            url_for("account.select_account")
        )  # Redirect to account selection page

    # Step 2: Fetch account details from the database
    account_details = Accounts.query.filter_by(id=account_alias).first()
    if not account_details:
        flash(
            "Account details not found. Please verify your account selection.",
            "error",
        )
        return redirect(url_for("account.select_account"))

    # Derive the S3 bucket name from the account details
    s3_bucket = account_details.s3_bucket
    if not s3_bucket:
        flash("S3 bucket not configured for this account.", "error")
        return redirect(url_for("account.select_account"))

    (
        aws_access_key_id,
        aws_secret_access_key,
        aws_session_token,
        region_name,
    ) = _extract_account_credentials(account_details)

    PROWLER_REPORTS_DIR = "prowler_reports"

    # Fetch the latest stored report keys from the database
    stored_keys = account_details.aws_prowler_compliance_report or ""
    if stored_keys:
        current_report_version = hashlib.sha256(
            stored_keys.encode("utf-8")
        ).hexdigest()
    else:
        current_report_version = None

    if session.get("aws_prowler_compliance_report_version") != current_report_version:
        session.pop("compliance_report", None)
        session.pop("json_report_url", None)

    if current_report_version is None:
        session.pop("aws_prowler_compliance_report_version", None)
    else:
        session["aws_prowler_compliance_report_version"] = current_report_version

    if session.get("compliance_report"):
        return render_template(
            "aws_compliance.html",
            compliance_report=session.get("compliance_report"),
            compliance_logo_links=compliance_logo_links,
            json_report_url=session.get("json_report_url"),
        )
    else:
        def handle_prowler_status():
            status = account_details.aws_prowler_check
            if status in ("pending", "running"):
                flash(
                    "Compliance check is in progress; please try again later",
                    "info",
                )
                return redirect(url_for("account.select_account"))
            if status == "failed":
                flash(
                    account_details.aws_prowler_compliance_report
                    or "Compliance check failed",
                    "error",
                )
                return redirect(url_for("account.select_account"))

        profile_name = f"{current_user.id}_{account_details.alias}"
        current_app.logger.info(
            "Raw aws_prowler_compliance_report: %s", stored_keys
        )
        try:
            keys = json.loads(stored_keys or "{}")
        except json.JSONDecodeError:
            current_app.logger.warning(
                "Failed to parse aws_prowler_compliance_report; attempting S3 lookup."
            )
            keys = {}
        if not isinstance(keys, dict):
            current_app.logger.warning(
                "aws_prowler_compliance_report parsed to %s, expected dict; treating as empty dict",
                type(keys).__name__,
            )
            keys = {}
        try:
            json_key = keys.get("json_report")
            pdf_keys = keys.get("pdf_reports", [])
        except AttributeError:
            current_app.logger.warning(
                "aws_prowler_compliance_report keys not a dict; treating as empty dict"
            )
            keys = {}
            json_key = None
            pdf_keys = []

        base_prefix = S3_REPORT_PREFIX.rstrip("/") + "/"
        active_prefix = base_prefix

        if not json_key:
            session_boto = _build_account_session(
                profile_name,
                aws_access_key_id,
                aws_secret_access_key,
                region_name,
                aws_session_token,
            )
            s3_client = (
                session_boto.client("s3", region_name=region_name)
                if region_name
                else session_boto.client("s3")
            )
            ensure_account_bucket(account_details.id, current_user.id, s3_bucket)
            s3_response = s3_client.list_objects_v2(
                Bucket=s3_bucket, Prefix=S3_REPORT_PREFIX
            )
            contents = s3_response.get("Contents", [])
            json_objects = [
                obj for obj in contents if obj["Key"].endswith(".json")
            ]
            pdf_objects = [
                obj for obj in contents if obj["Key"].endswith(".pdf")
            ]
            pdf_keys = [obj["Key"] for obj in pdf_objects]
            if json_objects:
                latest_obj = max(json_objects, key=lambda x: x["LastModified"])
                json_key = latest_obj["Key"]
                keys["json_report"] = json_key
                keys["pdf_reports"] = pdf_keys
                new_stored_keys = json.dumps(keys)
                account_details.aws_prowler_compliance_report = new_stored_keys
                db.session.commit()
                session["aws_prowler_compliance_report_version"] = hashlib.sha256(
                    new_stored_keys.encode("utf-8")
                ).hexdigest()
            else:
                response = handle_prowler_status()
                if response:
                    return response
                flash("No JSON report found in S3 bucket", "error")
                return redirect(url_for("account.select_account"))

        if json_key:
            if not json_key.startswith(base_prefix):
                json_key = f"{base_prefix}{json_key.lstrip('/')}"
            if "/" in json_key:
                active_prefix = json_key.rsplit("/", 1)[0] + "/"

        normalized_pdf_keys = []
        for key in pdf_keys:
            if not key:
                continue
            if not key.startswith(base_prefix):
                candidate = f"{active_prefix}{key.lstrip('/')}"
                if not candidate.startswith(base_prefix):
                    candidate = f"{base_prefix}{key.lstrip('/')}"
                key = candidate
            normalized_pdf_keys.append(key)
        pdf_keys = normalized_pdf_keys
        file_content, error_message, status_code = download_from_s3(
            s3_bucket,
            json_key,
            account_details.id,
            current_user.id,
            profile_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region=region_name,
        )
        if status_code != 200 or file_content is None:
            if status_code == 404:
                response = handle_prowler_status()
                if response:
                    return response
                flash("No reports found in S3 for this account", "error")
            else:
                flash(
                    f"Error retrieving compliance report from S3: {error_message}",
                    "error",
                )
            return redirect(url_for("account.select_account"))

        try:
            json_data = json.loads(file_content)
        except Exception:
            flash("Error parsing compliance report", "error")
            return redirect(url_for("account.select_account"))

        compliance_report = sorted(
            generate_reports_data(
                json_data,
                PROWLER_REPORTS_DIR,
                account_details.alias,
                current_user.id,
                storage_prefix=active_prefix,
            ),
            key=lambda x: x["finding_name"],
        )
        session_boto = _build_account_session(
            profile_name,
            aws_access_key_id,
            aws_secret_access_key,
            region_name,
            aws_session_token,
        )
        s3_client = (
            session_boto.client("s3", region_name=region_name)
            if region_name
            else session_boto.client("s3")
        )
        ensure_account_bucket(account_details.id, current_user.id, s3_bucket)

        # Pre-generate presigned URLs from stored report keys
        json_url = s3_client.generate_presigned_url(
            "get_object", Params={"Bucket": s3_bucket, "Key": json_key}
        )
        pdf_url_map = {
            key: s3_client.generate_presigned_url(
                "get_object", Params={"Bucket": s3_bucket, "Key": key}
            )
            for key in pdf_keys
        }

        expected_prefix = base_prefix
        for report in compliance_report:
            pdf_key = report["pdf"]
            if not pdf_key.startswith(expected_prefix):
                candidate = f"{active_prefix}{str(pdf_key).lstrip('/')}"
                if not candidate.startswith(expected_prefix):
                    candidate = f"{expected_prefix}{str(pdf_key).lstrip('/')}"
                pdf_key = candidate
                report["pdf"] = pdf_key
            report["pdf_url"] = pdf_url_map.get(
                pdf_key,
                s3_client.generate_presigned_url(
                    "get_object", Params={"Bucket": s3_bucket, "Key": pdf_key}
                ),
            )

        session["compliance_report"] = compliance_report
        session["json_report_url"] = json_url
        return render_template(
            "aws_compliance.html",
            compliance_report=compliance_report,
            compliance_logo_links=compliance_logo_links,
            json_report_url=json_url,
        )


@main.route("/download/<string:filename>", methods=["GET"])
def download_file(filename):
    """Download a report from S3 for the selected account."""
    try:
        account_id = session.get("selected_account")
        if not account_id:
            return "Account not selected.", 404

        account_details = Accounts.query.filter_by(
            id=account_id, user_id=current_user.id
        ).first()
        if not account_details or not account_details.s3_bucket:
            return "S3 bucket not configured for this account.", 404

        profile_name = f"{current_user.id}_{account_details.alias}"
        s3_key = filename
        if not s3_key.startswith(S3_REPORT_PREFIX):
            s3_key = f"{S3_REPORT_PREFIX}{s3_key}"
        (
            aws_access_key_id,
            aws_secret_access_key,
            aws_session_token,
            region_name,
        ) = _extract_account_credentials(account_details)
        file_content, error_message, status_code = download_from_s3(
            account_details.s3_bucket,
            s3_key,
            account_details.id,
            current_user.id,
            profile_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region=region_name,
        )

        if status_code == 404:
            return "No reports found in S3 for this account", 404
        if status_code != 200 or file_content is None:
            return error_message or "File not found.", status_code

        return send_file(
            io.BytesIO(file_content),
            download_name=os.path.basename(s3_key),
            as_attachment=True,
        )
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while processing your request.", 500


@main.route("/service-information", methods=["POST", "GET"])
@login_required
def service_info():
    """
    Handles service information page rendering.
    Uses session management to track the selected AWS account.
    """
    pop_session_if_already_exist()

    # Cache selected account to avoid redundant queries
    account = session.get("selected_account")
    if not account:
        account = (
            Accounts.query.with_entities(Accounts.id)
            .filter_by(account=current_user)
            .first()
        )
        if account:
            session["selected_account"] = account.id
        else:
            session["selected_account"] = None
    return render_template(
        "service-info.html", title=""
    )  # whatever you will put here value this will shown to page title


# Route to fetch the list of accounts (called by AJAX)
@app.route("/get_accounts", methods=["GET"])
def get_accounts():
    """
    Returns a list of AWS accounts (id and alias) associated with the current user.
    The list is limited to the first 9 characters of the alias for display purposes.
    """
    accounts = (
        Accounts.query.with_entities(Accounts.id, Accounts.alias)
        .filter_by(account=current_user)
        .all()
    )

    # Use list comprehension for efficiency, limiting alias to 9 characters
    return jsonify([(account.id, account.alias[:9]) for account in accounts])


@main.route("/get_account_details", methods=["GET"])
@login_required
def get_account_details():
    """Return details for a specific AWS account."""
    account_id = request.args.get("account_id", type=int)
    if account_id is None:
        return jsonify({"error": "Missing account_id"}), 400

    account = Accounts.query.get_or_404(account_id)
    if account.user_id != current_user.id:
        abort(404)

    return jsonify(
        {
            "alias": account.alias,
            "default_region_name": account.default_region_name,
            "access_key_id": account.access_key_id,
            "default_output_format": account.default_output_format,
        }
    )


@main.route("/set_account", methods=["POST"])
@login_required
def set_account():
    """
    Route to handle form submission to set the selected account.
    The account ID is saved in the session and user is redirected to the service info page.
    """
    # Set selected account in session securely
    session["selected_account"] = request.form.get("account")
    session.pop("compliance_report", None)
    # Redirect to service information with the selected account
    return redirect(url_for("account.service_info"))


@main.route("/select_account")
@login_required
def select_account():
    """
    Fetches AWS accounts associated with the current user.
    Optimizes database queries by using caching, improving both performance and security.
    """

    # If no cached data, query the database to fetch accounts
    accounts = (
        Accounts.query.with_entities(Accounts).filter_by(account=current_user).all()
    )

    # Convert query results into a list for rendering
    user_aws_accounts = [account for account in accounts]
    session.pop("compliance_report", None)
    # Render account selection template
    return render_template("select-account.html", user_aws_accounts=user_aws_accounts)


@main.route("/add-account", methods=["POST", "GET"])
@login_required  # Ensure only authenticated users can access this route
def add_account():
    """
    Route to handle adding a new AWS account for the logged-in user.

    Key Features:
    - Handles form submission for account creation.
    - Validates user input using Flask-WTF.
    - Configures the AWS CLI for the new account and runs security checks.
    - Inserts account details into the database securely.
    """
    form = AddAccountForm()

    # Handle POST request with form validation
    if form.validate_on_submit():
        alias = form.alias.data.strip()  # Strip whitespace to avoid errors
        access_key_id = form.access_key.data.strip()
        secret_access_key = form.secret_key.data.strip()
        default_region_name = form.default_region.data.strip()
        email_alias = f"{current_user.id}_{alias}"  # Unique email alias for AWS CLI

        try:
            # Configure AWS CLI for the new account
            success, configure_message = run_configure(
                access_key_id,
                secret_access_key,
                default_region_name,
                "json",
                email_alias,
            )

            if not success:
                flash(f"AWS CLI configuration failed: {configure_message}", "error")
                return redirect(url_for("account.add_account"))

            # Verify that the profile works and points to the correct account
            verified, verify_message = verify_aws_profile(email_alias)
            if not verified:
                flash(
                    f"AWS profile verification failed: {verify_message}", "error"
                )
                return redirect(url_for("account.add_account"))

            # Create a unique S3 bucket for this account
            unique_suffix = uuid.uuid4().hex[:8]
            bucket_name = f"aws-complitru-{unique_suffix}"
            session_boto = boto3.Session(profile_name=email_alias)
            s3_client = session_boto.client("s3")
            try:
                if default_region_name != "us-east-1":
                    s3_client.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={
                            "LocationConstraint": default_region_name
                        },
                    )
                else:
                    s3_client.create_bucket(Bucket=bucket_name)
            except Exception as e:
                flash(f"Could not create S3 bucket: {e}", "error")
                return redirect(url_for("account.add_account"))

            # Run Security Hub setup command for the new account
            success, securityhub_message = run_securityhub_command(
                current_user.email,
                alias,
                bucket_name,
                access_key_id,
                secret_access_key,
                default_region_name,
            )

            if not success:
                flash(f"{securityhub_message}", "error")
                return redirect(url_for("account.add_account"))

            securityhub_notice = (securityhub_message or "").strip()
            notice_lower = securityhub_notice.lower()
            securityhub_disabled = "security hub is not enabled" in notice_lower

            if securityhub_disabled and securityhub_notice:
                flash(securityhub_notice, "info")

            # Create new account object and commit to the database
            new_account = Accounts(
                alias=alias,
                access_key_id=access_key_id,
                secret_access_key=secret_access_key,
                default_region_name=default_region_name,
                default_output_format="json",  # Static value
                s3_bucket=bucket_name,
                account=current_user,  # Associate account with the current user
                date_created=datetime.utcnow(),
            )

            # Use atomic transaction for database operations
            db.session.add(new_account)
            db.session.commit()

            # Update session and cache
            session["selected_account"] = new_account.id
            cache.delete(f"user_accounts_{current_user.email}")

            # Flash success message and redirect
            success_flash = "Account added successfully."
            if securityhub_notice and not securityhub_disabled:
                success_flash = f"Account added successfully: {securityhub_notice}"
            flash(success_flash, "success")
            return redirect(url_for("account.select_account"))

        except Exception as e:
            # Rollback transaction in case of an error
            db.session.rollback()

            # Log detailed error for debugging purposes
            app.logger.error(f"Error adding AWS account: {e}")
            app.logger.error(traceback.format_exc())

            # Flash a generic error message to the user
            flash(
                "An unexpected error occurred while adding the account. Please try again.",
                "error",
            )
            return redirect(url_for("account.add_account"))

    # Render the form for GET requests or when validation fails
    return render_template("add-account.html", form=form)


@main.route("/delete_account/<int:acc_id>", methods=["POST", "GET"])
@login_required
def delete_account(acc_id):
    """
    Deletes the selected AWS account.
    Clears cache after deletion to ensure account list is up-to-date.
    """
    try:
        # Find the account by ID and delete it
        remove_account(acc_id)
        flash("Account deleted successfully", "success")
    except Exception as e:
        # Rollback transaction and log error if something goes wrong
        db.session.rollback()
        app.logger.error(f"Error deleting AWS account: {e}")
        traceback.print_exc()
        flash("An error occurred while deleting the account.", "error")

    return redirect(url_for("account.select_account"))


# Get all the data from the update form and update the fields under the account's alias in the RDS database
@main.route("/update_account", methods=["POST"])
@login_required
def update_account():
    # Get form data
    email = request.form["email"]
    alias = request.form["alias"]
    access_key_id = request.form["access_key_id"]
    secret_access_key = request.form["secret_access_key"]
    default_region_name = request.form["default_region_name"]
    default_output_format = "json"
    account = request.form["account"]

    account_u = Accounts.query.filter_by(account=account).first()

    account_u.alias = alias
    account_u.access_key_id = access_key_id
    account_u.secret_access_key = secret_access_key
    account_u.default_region_name = default_region_name
    account_u.default_output_format = default_output_format
    db.session.commit()

    # Drop any cached boto3 sessions so new credentials are used
    boto3.setup_default_session()

    # Refresh the AWS CLI profile with the new credentials
    email_alias = f"{current_user.id}_{alias}"
    run_configure(
        access_key_id,
        secret_access_key,
        default_region_name,
        default_output_format,
        email_alias,
    )

    # Call the function to run the securityhub command using explicit credentials
    run_securityhub_command(
        email,
        alias,
        account_u.s3_bucket,
        account_u.access_key_id,
        account_u.secret_access_key,
        account_u.default_region_name,
        account_u.id,
        current_user.id,
    )

    # Redirect back to the manage page
    return redirect(url_for("account.select_account", email=email))



@main.route("/update_account/<int:account_id>", methods=["PUT"])
@login_required
def update_account_api(account_id):
    data = request.get_json() or {}
    alias = (data.get("alias") or "").strip()
    access_key_id = (data.get("access_key_id") or "").strip()
    secret_access_key = data.get("secret_access_key")
    default_region_name = (data.get("default_region_name") or "").strip()

    if not alias or not access_key_id or not default_region_name:
        return jsonify({"message": "Alias, Access Key, and Region are required"}), 400

    try:
        account_u = Accounts.query.get_or_404(account_id)
        account_u.alias = alias
        account_u.access_key_id = access_key_id
        if secret_access_key is not None:
            secret_access_key = secret_access_key.strip()
            if secret_access_key:
                account_u.secret_access_key = secret_access_key
        account_u.default_region_name = default_region_name
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        current_app.logger.error(f"Error updating account: {exc}")
        return jsonify({"message": "Failed to update account"}), 500

    # Drop any cached boto3 sessions so new credentials are used
    boto3.setup_default_session()

    # Determine the effective secret key
    effective_secret = (
        secret_access_key.strip()
        if secret_access_key and secret_access_key.strip()
        else account_u.secret_access_key
    )

    # Refresh the AWS CLI profile with the updated credentials
    email_alias = f"{current_user.id}_{alias}"
    success, configure_message = run_configure(
        access_key_id,
        effective_secret,
        default_region_name,
        "json",
        email_alias,
    )
    if not success:
        current_app.logger.error(
            f"AWS CLI configuration failed for profile {email_alias}: {configure_message}"
        )
        return (
            jsonify({"message": f"Failed to configure AWS profile: {configure_message}"}),
            500,
        )

    # Optionally verify the AWS profile to ensure credentials are valid
    verified, verify_message = verify_aws_profile(email_alias)
    if not verified:
        current_app.logger.error(
            f"AWS profile verification failed for {email_alias}: {verify_message}"
        )
        return (
            jsonify({"message": f"AWS profile verification failed: {verify_message}"}),
            400,
        )

    return jsonify({"message": "Account updated successfully"}), 200

# ----------------------- Report Generation Routes -----------------------


@main.route("/generate_report")
@login_required  # Ensure only authenticated users can access this route
def generate_report():
    """
    Generates and returns the HIPAA compliance report as a downloadable PDF.
    """
    report = session.get("report")  # Retrieve the report from the session
    if not report:
        flash("No report data found in session", "error")
        return redirect(url_for("account.hipaa_report"))

    # Generate the PDF using the retrieved report data
    pdf_buffer = generate_hipaa_report(report)

    # Securely send the file as an attachment to be downloaded
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name="HIPAA_Compliance_Report.pdf",
        mimetype="application/pdf",
    )


@main.route("/generate_pci_report")
@login_required
def generate_pci_report():
    """
    Generates and returns the PCI compliance report as a downloadable PDF.
    """
    report = session.get("report")
    if not report:
        flash("No report data found in session", "error")
        return redirect(url_for("account.pci_report"))

    pdf_buffer = generate_pdf_report(report)
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name="PCI_Compliance_Report.pdf",
        mimetype="application/pdf",
    )


# ----------------------- Report Display Routes -----------------------


@main.route("/hipaa_report")
@login_required
def hipaa_report():
    """
    Displays the HIPAA compliance report on a web page.
    Ensures that session data exists or performs compliance checks to generate the report.
    """
    report = session.get("report")

    # If report data isn't in session, perform compliance checks and store the result
    if not report:
        session["report"] = perform_compliance_checks()
        report = session.get("report")

    # Render the HIPAA report page with the necessary report data
    return render_template(
        "hipaa.html",
        report=report,
        get_remediation_steps=get_remediation_steps,
        get_section_explanation=get_section_explanation,
    )


@main.route("/pci_report")
@login_required
def pci_report():
    """
    Displays the PCI compliance report on a web page.
    Performs compliance checks if report data is absent from the session.
    """
    report = session.get("report")

    if not report:
        session["report"] = perform_compliance_checks()
        report = session.get("report")

    return render_template(
        "pci.html",
        report=report,
        get_remediation_steps=get_remediation_steps,
        get_section_explanation=get_section_explanation,
    )


# ----------------------- Vulnerability Report Route -----------------------


@main.route("/vulnerability", methods=["GET"])
@login_required  # Restrict access to logged-in users
def vulnerability():
    """
    Displays vulnerability findings for the selected AWS account.
    - Retrieves findings from S3 or falls back to a local file for testing.
    - Ensures data is decoded properly using various encodings.
    - Sorts findings by severity and groups them by title to reduce redundancy.
    - Displays results on the 'vulnerability.html' page.

    Returns:
        Rendered HTML template with account details and vulnerability findings.
    """

    # Step 1: Validate session for selected account
    account_alias = session.get("selected_account")
    if not account_alias:
        flash("No account selected. Please select an account first.", "error")
        return redirect(
            url_for("account.select_account")
        )  # Redirect to account selection page

    # Step 2: Fetch account details from the database
    account_details = Accounts.query.filter_by(id=account_alias).first()
    if not account_details:
        flash(
            "Account details not found. Please verify your account selection.", "error"
        )
        return redirect(url_for("account.select_account"))

    # Step 2.1: Retrieve the S3 bucket for this account
    s3_bucket = account_details.s3_bucket
    if not s3_bucket:
        flash("S3 bucket not configured for this account.", "error")
        return redirect(url_for("account.select_account"))

    # Step 3: Validate current user's email
    email = current_user.email
    if not email:
        flash("Unable to retrieve user email. Please log in again.", "error")
        return redirect(url_for("auth.login"))  # Redirect to login page

    # Step 4: Construct S3 key for retrieving findings
    s3_key = f"{email}~{account_details.alias}.json"
    email_alias = f"{current_user.id}_{account_details.alias}"

    # Step 5: Download findings data from S3
    (
        aws_access_key_id,
        aws_secret_access_key,
        aws_session_token,
        region_name,
    ) = _extract_account_credentials(account_details)
    file_content, error_message, status_code = download_from_s3(
        s3_bucket,
        s3_key,
        account_details.id,
        current_user.id,
        email_alias,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
        region=region_name,
    )
    if status_code != 200:
        if status_code == 404:
            # Fall back to a local sample file if the S3 object is missing
            local_file = os.path.join(
                app.root_path, "sample_data", "sample_vulnerabilities.json"
            )
            try:
                with open(local_file, "rb") as f:
                    file_content = f.read()
            except FileNotFoundError:
                flash(f"Error retrieving data from S3: {error_message}", "error")
                return redirect(
                    url_for("account.service_info")
                )  # Redirect to service info page
        else:
            flash(f"Error retrieving data from S3: {error_message}", "error")
            return redirect(
                url_for("account.service_info")
            )  # Redirect to service info page

    # Step 6: Decode findings content using multiple encodings
    findings = None
    encoding_options = ["utf-8", "utf-16", "utf-32", "latin-1"]
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    for encoding in encoding_options:
        try:
            # Attempt to decode file content
            decoded_content = file_content.decode(encoding)
            findings = json.loads(decoded_content)

            # Sort findings by severity if successfully decoded
            findings.sort(
                key=lambda x: severity_order.get(x.get("Severity", ""), float("inf"))
            )
            break  # Exit loop if decoding and sorting are successful
        except (UnicodeDecodeError, json.JSONDecodeError):
            # Log the failed decoding attempt (use a logger if available)
            print(f"Decoding failed for encoding: {encoding}")
            continue  # Try the next encoding if current one fails

    if findings is None:
        flash("Unable to decode findings file. Please check the file format.", "error")
        return redirect(url_for("account.service_info"))

    # Step 7: Group findings by title to reduce redundancy
    grouped_findings = {}
    for finding in findings:
        title = finding.get(
            "Title", "Unknown Title"
        )  # Use default title if not present
        grouped_findings.setdefault(title, []).append(finding)

    # Step 8: Render the vulnerability report page
    return render_template(
        "vulnerability.html",
        account=account_details.alias,  # AWS account alias
        findings=findings,  # Sorted findings list
        grouped_findings=grouped_findings,  # Findings grouped by title
        email=email,  # Current user's email
    )


@main.route("/execute_command", methods=["POST"])
@login_required
def execute_command():
    """
    Execute a shell command sent via POST request in JSON format.
    Returns the command output or an error message in JSON response.
    """
    # Check if the request contains JSON data
    if not request.is_json:
        return jsonify({"error": "Unsupported Media Type, JSON expected"}), 415

    # Extract the command from the JSON payload
    command = request.json.get("command")
    if not command:
        return jsonify({"error": "Command not provided"}), 400

    account_alias = session.get("selected_account")
    # Step 2: Fetch account details from the database
    account_details = Accounts.query.filter_by(id=account_alias).first()
    if not account_details:
        return jsonify({"error": "Account not found"}), 400

    email_alias = f"{current_user.id}_{account_details.alias}"
    args = shlex.split(command)
    args.extend(["--profile", email_alias])
    try:
        # Use subprocess.run to execute the command securely
        result = subprocess.run(
            # command,
            # capture_output=True,  # Capture stdout and stderr
            # text=True,  # Decode output as text
            # check=True,  # Raise exception on non-zero exit codes
            args,
            capture_output=True,
            text=True,
            check=True,
        )

        # Extract command output and error (if any)
        output = result.stdout.strip()  # Remove trailing whitespace
        error = result.stderr.strip()  # Remove trailing whitespace

        # Return success response with output and error (if any)
        return (
            jsonify(
                {
                    "status": "success",
                    "command": command,
                    "output": output,
                    "error": error,
                }
            ),
            200,
        )

    except FileNotFoundError:
        return jsonify({"status": "failure", "error": "AWS CLI not found"}), 500

    except subprocess.CalledProcessError as e:
        # Handle errors raised during command execution
        return (
            jsonify(
                {
                    "status": "failure",
                    "error": str(e),
                    "output": e.output.strip() if e.output else None,
                    "stderr": e.stderr.strip() if e.stderr else None,
                }
            ),
            400,
        )

    except Exception as ex:
        # Handle unexpected errors
        return jsonify({"error": "Internal Server Error", "details": str(ex)}), 500


# @app.route("/gpt_result", methods=["POST"])
# @login_required
# def gpt_result():
#     finding_json = request.json.get("finding_json")
#     print(finding_json)
#     if not finding_json:
#         return jsonify({"error": "No JSON data received"}), 400

#     # Dummy GPT Response for testing
#     dummy_completion_dict = {
#         "id": "chatcmpl-9ga5LdQstEUiSLLuSSxsyrHoafylB",
#         "choices": [
#             {
#                 "finish_reason": "stop",
#                 "index": 0,
#                 "logprobs": None,
#                 "message": {
#                     "content": (
#                         "### List all available AWS CLI commands:\n\n"
#                         "**Description:** Get a list of all AWS CLI commands to see what actions are available.\n\n"
#                         "**AWS CLI Command:**\n"
#                         "```\naws --version\n\n"
#                     ),
#                     "role": "assistant",
#                     "function_call": None,
#                     "tool_calls": None,
#                 },
#             }
#         ],
#         "created": 1719935515,
#         "model": "gpt-3.5-turbo-0125",
#         "object": "chat.completion",
#         "service_tier": None,
#         "system_fingerprint": None,
#         "usage": {"completion_tokens": 301, "prompt_tokens": 477, "total_tokens": 778},
#     }

#     try:
#         completion = gpt_client.chat.completions.create(
#             model="gpt-4o",  # model="gpt-4o",
#             messages=[
#                 {
#                     "role": "system",
#                     "content": "You are a Security Engineer, with an understanding of AWS CLI and AWS Security hub. Using security findings in json format, you provide remediation steps and AWS CLI commands. Do not output what is already in the json like the description or title. Give well formatted numbered list with the steps (each step has Description, AWS CLI command, Note), additional steps, etc.",
#                 },
#                 {
#                     "role": "user",
#                     "content": f"I have an AWS resource described in the following JSON format. Please analyze the JSON to identify any security vulnerabilities and provide the exact AWS CLI command(s) to remediate these vulnerabilities. The goal is to automate the fix without any additional explanation and without replacing ANYTHING, I want to execute the CLI commands given to me directly! Here is the JSON data for the AWS resource. Security Finding JSON: {finding_json}",
#                 },
#             ],
#         )
#         print(completion.model_dump_json())
#         completion_dict = json.loads(completion.model_dump_json())
#         response_message = completion_dict["choices"][0]["message"]["content"]
#         response_html = markdown2.markdown(response_message)
#         aws_cli_commands = extract_aws_cli_commands(response_message)

#         response_data = {
#             "updated_finding": response_html,
#             "aws_cli_commands": aws_cli_commands,
#             # Include AWS CLI commands in response
#         }

#         return jsonify(response_data), 200

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

# # Create a Bedrock Runtime client (use proper AWS credentials or IAM role)
@app.route("/gpt_result", methods=["POST"])
@login_required
def gpt_result():
    finding_json = request.json.get("finding_json")
    print(finding_json)
    if not finding_json:
        return jsonify({"error": "No JSON data received"}), 400

    # Prompt engineering for Claude
    prompt = f"""
    Human:
    You are an experienced AWS Security Engineer. Your task is to review the following AWS Security Hub finding (in JSON format) and generate a set of accurate, production-ready AWS CLI remediation commands.

    Requirements:
    1. Return a numbered list of steps.
    2. Each step must include:
    - **Description**: Clearly describe what the command does in business terms.
    - **AWS CLI Command**: Provide the exact command with appropriate parameters.
    - **Note**: Add context or warnings if necessary (e.g., impact, prerequisites).

    Guidelines:
    - Keep the language concise, clear, and professional.
    - Ensure the format is clean and well-structured for developers or DevOps teams.
    - Avoid repeating the title or description from the JSON.
    - Use modern best practices where applicable.

    Input: 
    Security Finding JSON:
    {finding_json}

    Assistant:
    """

    try:
        bedrock_runtime = boto3.client("bedrock-runtime", region_name="us-east-1")
        response = bedrock_runtime.invoke_model(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            contentType="application/json",
            accept="application/json",
            body=json.dumps(
                {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 1024,
                    "temperature": 0.2,
                    "messages": [{"role": "user", "content": prompt}],
                }
            ),
        )

        result = json.loads(response["body"].read())
        response_message = result["content"][0]["text"]

        response_html = markdown2.markdown(response_message)

        # Optional: parse out CLI commands
        aws_cli_commands = extract_aws_cli_commands(response_message)

        return (
            jsonify(
                {
                    "updated_finding": response_html,
                    "aws_cli_commands": aws_cli_commands,
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@main.route("/nova_sonic_agent", methods=["POST"])
@login_required
def nova_sonic_agent():
    """Voice-enabled assistant that leverages account intelligence."""

    if not app.config.get("OPENAI_API_KEY"):
        return (
            jsonify(
                {
                    "error": "Nova-Sonic agent is not configured. Contact your administrator.",
                }
            ),
            503,
        )

    if not request.is_json:
        return jsonify({"error": "JSON body expected"}), 415

    payload = request.get_json() or {}
    user_message = (payload.get("message") or "").strip()
    audio_b64 = payload.get("audio")
    transcription: str | None = None

    if audio_b64:
        if isinstance(audio_b64, str) and audio_b64.startswith("data:"):
            audio_b64 = audio_b64.split(",", 1)[1]
        try:
            audio_bytes = base64.b64decode(audio_b64)
        except (ValueError, TypeError) as exc:
            return jsonify({"error": "Invalid audio payload", "details": str(exc)}), 400

        audio_buffer = io.BytesIO(audio_bytes)
        audio_buffer.name = payload.get("audio_filename", "nova-sonic.webm")

        try:
            transcript = gpt_client.audio.transcriptions.create(
                model=app.config.get("NOVA_SONIC_TRANSCRIBE_MODEL", "whisper-1"),
                file=audio_buffer,
            )
        except Exception as exc:  # pragma: no cover - depends on external service
            current_app.logger.exception("Nova-Sonic transcription failed")
            return (
                jsonify({"error": "Failed to transcribe audio", "details": str(exc)}),
                502,
            )

        transcription = getattr(transcript, "text", None)
        if transcription and not user_message:
            user_message = transcription

    if not user_message:
        return jsonify({"error": "Provide a question or audio clip to analyse."}), 400

    account_alias = session.get("selected_account")
    if not account_alias:
        return (
            jsonify({"error": "Select an AWS account before contacting Nova-Sonic."}),
            400,
        )

    account_details = Accounts.query.filter_by(
        id=account_alias, user_id=current_user.id
    ).first()
    if not account_details:
        return jsonify({"error": "Account not found or not accessible."}), 404

    context = build_nova_sonic_context(account_details, current_user)
    context_payload = context.to_prompt_dict()
    context_json = json.dumps(context_payload, indent=2)

    system_prompt = (
        "You are Nova-Sonic, a cloud compliance, security, vulnerability, and cost analysis "
        "expert. You provide grounded guidance using the supplied AWS account intelligence. "
        "Be concise but comprehensive, cite the data points you rely on, and highlight "
        "material risks, compliance gaps, and optimisation opportunities. If critical data "
        "is missing, state what is required.""
    )

    user_prompt = (
        "Respond to the user question using the following account context.\n\n"
        f"User question: {user_message}\n\n"
        f"Account intelligence (JSON):\n{context_json}\n\n"
        "Structure your answer with Markdown headings for 'Executive Summary', "
        "'Key Findings', and 'Recommended Actions'. Include cost analysis, compliance "
        "status, and security remediation recommendations.""
    )

    try:
        completion = gpt_client.chat.completions.create(
            model=app.config.get("NOVA_SONIC_MODEL", "gpt-4o-mini"),
            temperature=0.2,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        response_message = completion.choices[0].message.content
    except Exception as exc:  # pragma: no cover - depends on external service
        current_app.logger.exception("Nova-Sonic completion failed")
        return (
            jsonify({"error": "Unable to generate Nova-Sonic response", "details": str(exc)}),
            502,
        )

    response_html = markdown2.markdown(response_message)

    return (
        jsonify(
            {
                "message": response_message,
                "html": response_html,
                "transcription": transcription,
                "context": context_payload,
                "model": app.config.get("NOVA_SONIC_MODEL", "gpt-4o-mini"),
            }
        ),
        200,
    )


# import boto3
# import json
# import markdown2
# from flask import request, jsonify
# from flask_login import login_required

# # Create a Bedrock Runtime client (make sure AWS credentials or IAM role has permissions)
# bedrock_runtime = boto3.client("bedrock-runtime", region_name="us-east-1")

# @app.route("/gpt_result", methods=["POST"])
# @login_required
# def gpt_result():
#     finding_json = request.json.get("finding_json")
#     if not finding_json:
#         return jsonify({"error": "No JSON data received"}), 400

#     # Build prompt for Titan
#     prompt = f"""
# You are a Security Engineer with expertise in AWS CLI and AWS Security Hub. Analyze the following AWS Security Hub finding JSON and return a list of exact AWS CLI commands to remediate any issues identified.

# Format the output using a numbered list. For each step, include:
# - **Description**: The purpose of the command
# - **AWS CLI Command**: The exact command
# - **Note**: Any additional note or warning

# Only respond with CLI commands and remediation steps. Do not repeat the title or description in the JSON.

# Security Finding JSON:
# {json.dumps(finding_json, indent=2)}
# """

#     try:
#         response = bedrock_runtime.invoke_model(
#             modelId="amazon.titan-text-premier-v1:0",
#             contentType="application/json",
#             accept="application/json",
#             body=json.dumps({
#                 "inputText": prompt,
#                 "textGenerationConfig": {
#                     "maxTokenCount": 1024,
#                     "temperature": 0.3,
#                     "topP": 0.9
#                 }
#             })
#         )

#         result = json.loads(response["body"].read())
#         response_message = result.get("results", [{}])[0].get("outputText", "")

#         response_html = markdown2.markdown(response_message)
#         aws_cli_commands = extract_aws_cli_commands(response_message)

#         return jsonify({
#             "updated_finding": response_html,
#             "aws_cli_commands": aws_cli_commands,
#         }), 200

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


@main.route("/download_csv/<email>/<alias>")
@login_required
def download_csv(email, alias):
    """
    Download Security Findings as a CSV File
    - Fetches a JSON file from S3, decodes it, converts it to CSV format, and sends it as a downloadable file.

    Parameters:
        email (str): Email associated with the file.
        alias (str): Alias associated with the file.

    Returns:
        Flask Response: A downloadable CSV file or an error message if an issue occurs.
    """

    # Step 0: Fetch account details to obtain the S3 bucket
    account_details = Accounts.query.filter_by(
        alias=alias, account=current_user
    ).first()
    if not account_details or not account_details.s3_bucket:
        return "Account details not found.", 404
    s3_bucket = account_details.s3_bucket

    # Step 1: Construct the S3 key and load file from S3
    s3_key = f"{email}~{alias}.json"
    email_alias = f"{current_user.id}_{alias}"

    # Attempt to download the file from S3
    (
        aws_access_key_id,
        aws_secret_access_key,
        aws_session_token,
        region_name,
    ) = _extract_account_credentials(account_details)
    file_content, error_message, status_code = download_from_s3(
        s3_bucket,
        s3_key,
        account_details.id,
        current_user.id,
        email_alias,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
        region=region_name,
    )

    # Handle S3 download errors with local fallback
    if status_code != 200:
        if status_code == 404:
            local_file = os.path.join(
                app.root_path, "sample_data", "sample_vulnerabilities.json"
            )
            try:
                with open(local_file, "rb") as f:
                    file_content = f.read()
            except FileNotFoundError:
                return error_message, status_code
        else:
            return error_message, status_code

    # Step 2: Attempt to decode the file content
    encodings = ["utf-8", "latin-1", "utf-16", "utf-32"]  # List of encodings to try
    findings = None

    for encoding in encodings:
        try:
            decoded_content = file_content.decode(
                encoding
            )  # Decode using the current encoding
            findings = json.loads(
                decoded_content
            )  # Attempt to parse the decoded content as JSON
            break  # Exit the loop on successful decoding
        except (UnicodeDecodeError, json.JSONDecodeError, UnicodeError):
            continue  # Continue to the next encoding on failure

    # Handle case where decoding or JSON parsing fails for all encodings
    if findings is None:
        return "Failed to read the JSON file with all attempted encodings", 500

    # Step 3: Prepare the CSV file in memory
    try:
        csv_file = io.StringIO()  # Create an in-memory text stream for the CSV file
        csv_writer = csv.writer(csv_file)

        # Write the header row (keys from the first finding)
        headers = findings[0].keys() if findings else []
        csv_writer.writerow(headers)

        # Write the data rows
        for finding in findings:
            csv_writer.writerow(finding.values())

        # Move to the beginning of the StringIO object for reading
        csv_file.seek(0)
    except Exception as e:
        return f"Error processing the findings into a CSV: {e}", 500

    # Step 4: Send the CSV file as a downloadable response
    try:
        return send_file(
            io.BytesIO(
                csv_file.getvalue().encode("utf-8")
            ),  # Convert StringIO to BytesIO for Flask response
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"{email}~{alias}.csv",  # Set the download file name
        )
    except Exception as e:
        return f"Error generating the CSV download response: {e}", 500


@main.route("/cost-optimization", methods=["POST", "GET"])
@login_required
def cost_optimization():
    """Cost Optimization - Daily Data for the Last 30 Days and Current Month"""

    # Step 1: Validate session for selected account
    account_alias = session.get("selected_account")
    if not account_alias:
        flash("No account selected. Please select an account to proceed.", "error")
        return redirect(url_for("account.select_account"))

    # Step 2: Fetch account details from the database
    account_details = Accounts.query.filter_by(id=account_alias).first()
    if not account_details:
        flash("Invalid or missing account details. Please try again.", "error")
        return redirect(url_for("account.select_account"))

    # Step 3: Validate account configuration (API keys and region)
    if not all(
        [
            account_details.access_key_id,
            account_details.secret_access_key,
            account_details.default_region_name,
        ]
    ):
        flash(
            "Account configuration is incomplete. Please ensure access keys and region are correctly set.",
            "error",
        )
        return redirect(url_for("account.select_account"))

    # Step 4: Define date ranges
    try:
        START_DATE = datetime.today().replace(day=1)
        END_DATE = datetime.today()
        if request.method == "POST":
            selected_month = request.form.get("selected_month")
            if selected_month:
                session["selected_month"] = selected_month
                START_DATE = datetime.strptime(selected_month, "%Y, %b %d")
                END_DATE = (START_DATE.replace(day=1) + timedelta(days=31)).replace(
                    day=1
                ) - timedelta(days=1)

        current_month_start = START_DATE
        current_month_end = END_DATE  # End date is today's date

        # Format dates for display
        formatted_start_date = START_DATE.strftime("%Y, %b %d")
        formatted_current_start_date = current_month_start.strftime("%Y, %b %d")
        formatted_end_date = END_DATE.strftime("%Y, %b %d")
    except Exception as e:
        flash(f"Error calculating date ranges: {e}", "error")
        return redirect(url_for("main.cost_optimization_home"))

    # Step 5: Fetch billing data from the AWS API
    try:
        billing_data = fetch_and_cache_billing_data(
            account_details.access_key_id,
            account_details.secret_access_key,
            account_details.default_region_name,
            START_DATE.strftime("%Y-%m-%d"),
            END_DATE.strftime("%Y-%m-%d"),
            granularity="DAILY",
        )
        # Handle the case where no billing data is returned
        if not billing_data:
            flash("No billing data available for the selected period.", "info")
            billing_data = []
    except Exception as e:
        flash(f"Error fetching billing data: {e}", "error")
        return redirect(url_for("main.cost_optimization_home"))

    # Step 6: Process billing data
    try:
        service_data = defaultdict(
            lambda: {"dates": [], "costs": [], "usage_quantities": []}
        )
        service_totals = defaultdict(float)  # Total cost per service
        current_month_cost = 0  # Total cost for the current month
        daily_cost = defaultdict(float)  # Daily cost breakdown

        for record in billing_data:
            service_name = record.get("Service", "Unknown Service")
            cost = float(record.get("Cost (USD)", 0))
            usage = float(record.get("UsageQuantity", 0))
            date = record.get("Date", "Unknown Date")

            # Group data by service
            service_data[service_name]["dates"].append(date)
            service_data[service_name]["costs"].append(cost)
            service_data[service_name]["usage_quantities"].append(usage)

            # Accumulate service totals
            service_totals[service_name] += cost

            # Accumulate current month's cost
            if (
                current_month_start.strftime("%Y-%m-%d")
                <= date
                <= current_month_end.strftime("%Y-%m-%d")
            ):
                current_month_cost += cost

            # Accumulate daily costs
            daily_cost[date] += cost

        # Identify the highest spent service
        highest_spent_service = max(
            service_totals, key=service_totals.get, default=None
        )
        highest_spent_amount = service_totals.get(highest_spent_service, 0)

        # Sort services by total cost (highest first)
        sorted_services = sorted(
            service_totals.items(), key=lambda x: x[1], reverse=True
        )
        sorted_service_data = {
            service: service_data[service] for service, _ in sorted_services
        }

        # Sort daily costs for visualization
        sorted_dates = sorted(daily_cost.keys())
        sorted_costs = [daily_cost[daily_date] for daily_date in sorted_dates]
    except Exception as e:
        flash(f"Error processing billing data: {e}", "error")
        return redirect(url_for("main.cost_optimization_home"))

    # Step 7: Render the cost optimization page
    try:
        return render_template(
            "cost_opt.html",
            total_cost=round(sum(sorted_costs), 2),  # Total cost for the billing period
            service_data=sorted_service_data,  # Service-specific breakdown
            highest_spent_service=highest_spent_service,  # Most expensive service
            highest_spent_amount=round(
                highest_spent_amount, 2
            ),  # Cost of the most expensive service
            service_totals=service_totals,  # Total costs per service
            current_month_cost=round(
                current_month_cost, 2
            ),  # Total cost for the current month
            billing_period=f"{formatted_start_date} to {formatted_end_date}",  # Billing period
            current_period=f"{formatted_current_start_date} to {formatted_end_date}",  # Current month period
        )
    except Exception as e:
        flash(f"Error rendering the cost optimization page: {e}", "error")
        return redirect(url_for("main.cost_optimization_home"))


@main.route("/cost-optimization-home")
@login_required
def cost_optimization_home():
    """Cost Optimization Home - Monthly and Daily Data with Validations"""
    # 1. Validate session for selected account
    account_alias = session.get("selected_account")
    if not account_alias:
        flash("No account selected. Please select an account to proceed.", "error")
        return redirect(url_for("account.select_account"))

    # 2. Fetch account details
    account_details = Accounts.query.filter_by(id=account_alias).first()
    if not account_details:
        flash("Invalid account selected. Please try again.", "error")
        return redirect(url_for("account.select_account"))

    # 3. Validate API keys and region
    if not all(
        [
            account_details.access_key_id,
            account_details.secret_access_key,
            account_details.default_region_name,
        ]
    ):
        flash(
            "Account configuration is incomplete. Ensure access keys and region are properly set.",
            "error",
        )
        return redirect(url_for("account.select_account"))

    # 4. Define date ranges and validate them
    try:
        today = date.today()
        START_DATE_MONTHLY = (today.replace(day=1) - timedelta(days=365)).strftime(
            "%Y-%m-%d"
        )  # Last 12 months
        START_DATE_DAILY = today.replace(day=1).strftime(
            "%Y-%m-%d"
        )  # Start of current month
        END_DATE = today.strftime("%Y-%m-%d")
        LAST_MONTH_START = (
            (today.replace(day=1) - timedelta(days=1))
            .replace(day=1)
            .strftime("%Y-%m-%d")
        )
        LAST_MONTH_END = today.replace(day=1).strftime("%Y-%m-%d")
    except Exception as e:
        flash(f"Error calculating date ranges: {str(e)}", "error")
        return redirect(url_for("account.select_account"))

    # 5. Fetch monthly data and validate
    try:
        monthly_data = fetch_and_cache_billing_data(
            account_details.access_key_id,
            account_details.secret_access_key,
            account_details.default_region_name,
            START_DATE_MONTHLY,
            END_DATE,
            granularity="MONTHLY",
        )
        if not monthly_data:
            flash("No monthly data available for the selected account.", "info")
            monthly_data = []
    except Exception as e:
        flash(f"Error fetching monthly data: {str(e)}", "error")
        return redirect(url_for("account.select_account"))

    # 6. Calculate total cost and validate
    try:
        total_cost = sum(float(record.get("Cost (USD)", 0)) for record in monthly_data)
    except Exception as e:
        flash(f"Error calculating total cost: {str(e)}", "error")
        total_cost = 0

    # 7. Fetch daily data and validate
    try:
        daily_data = fetch_and_cache_billing_data(
            account_details.access_key_id,
            account_details.secret_access_key,
            account_details.default_region_name,
            START_DATE_DAILY,
            END_DATE,
            granularity="DAILY",
        )
        if not daily_data:
            flash("No daily data available for the selected account.", "info")
            daily_data = []
    except Exception as e:
        flash(f"Error fetching daily data: {str(e)}", "error")
        return redirect(url_for("account.select_account"))

    # 9. Summarize monthly cost
    try:
        monthly_cost = defaultdict(float)
        for record in monthly_data:
            record_date = datetime.strptime(record["Date"], "%Y-%m-%d")
            month_year = record_date.strftime("%b %Y")
            monthly_cost[month_year] += float(record.get("Cost (USD)", 0))
        sorted_months = sorted(
            monthly_cost.keys(), key=lambda x: datetime.strptime(x, "%b %Y")
        )
        sorted_monthly_costs = [monthly_cost[month] for month in sorted_months]
    except Exception as e:
        flash(f"Error summarizing monthly costs: {str(e)}", "error")
        sorted_months = []
        sorted_monthly_costs = []

    # 10. Calculate MTD cost and forecasted cost
    try:
        mtd_cost = sum(float(record.get("Cost (USD)", 0)) for record in daily_data)
        forecasted_cost = (mtd_cost / today.day) * 30 if today.day > 0 else 0
    except Exception as e:
        flash(f"Error calculating MTD/forecasted cost: {str(e)}", "error")
        mtd_cost = 0
        forecasted_cost = 0

    # 11. Calculate last month's total cost and same time period cost
    try:
        last_month_total_cost = sum(
            float(record.get("Cost (USD)", 0))
            for record in monthly_data
            if LAST_MONTH_START <= record["Date"] < LAST_MONTH_END
        )
        last_month_same_period_cost = sum(
            float(record.get("Cost (USD)", 0))
            for record in daily_data
            if LAST_MONTH_START <= record["Date"] < LAST_MONTH_END
        )
    except Exception as e:
        flash(f"Error calculating last month's costs: {str(e)}", "error")
        last_month_total_cost = 0
        last_month_same_period_cost = 0

    # 12. Prepare service breakdown data
    try:
        service_costs = defaultdict(float)
        for record in daily_data:
            service_costs[record["Service"]] += float(record.get("Cost (USD)", 0))
        services_breakdown = [
            {"name": service, "y": cost} for service, cost in service_costs.items()
        ]
    except Exception as e:
        flash(f"Error preparing service breakdown: {str(e)}", "error")
        services_breakdown = []
    # 9. Validate highest service calculation from services_breakdown
    try:
        highest_service = max(
            services_breakdown, key=lambda x: x["y"], default={"name": "N/A", "y": 0}
        )
    except ValueError:
        highest_service = {"name": "N/A", "y": 0}
    return render_template(
        "cost_opt_home.html",
        data=daily_data,
        months=sorted_months,
        monthly_costs=sorted_monthly_costs,
        mtd_cost=round(mtd_cost, 2),
        total_cost=round(total_cost, 2),
        forecasted_cost=round(forecasted_cost, 2),
        last_month_total_cost=round(last_month_total_cost, 2),
        last_month_same_period_cost=round(last_month_same_period_cost, 2),
        services_breakdown=services_breakdown,
        highest_service={
            "service": highest_service.get("name", "N/A"),
            "cost": round(highest_service.get("y", 0), 2),
        },
    )


@main.route("/Compliance-check-aws")
@login_required
def compliance_check_aws():
    """Cost Optimization Home - Monthly and Daily Data with Validations"""
    # 1. Validate session for selected account
    account_alias = session.get("selected_account")
    if not account_alias:
        flash("No account selected. Please select an account to proceed.", "error")
        return redirect(url_for("account.select_account"))

    # 2. Fetch account details
    account_details = Accounts.query.filter_by(id=account_alias).first()
    if not account_details:
        flash("Invalid account selected. Please try again.", "error")
        return redirect(url_for("account.select_account"))

    # 3. Validate API keys and region
    if not all(
        [
            account_details.access_key_id,
            account_details.secret_access_key,
            account_details.default_region_name,
        ]
    ):
        flash(
            "Account configuration is incomplete. Ensure access keys and region are properly set.",
            "error",
        )
        return redirect(url_for("account.select_account"))

    return render_template("aws_compliance.html")


@main.route("/cost-optimization/download-csv")
@login_required
def cost_optimization_csv():
    """Download CSV for Daily Cost Optimization Data with Validations"""
    # 1. Validate session for selected account
    account_alias = session.get("selected_account")
    if not account_alias:
        flash("No account selected. Please select an account to proceed.", "error")
        return redirect(url_for("account.select_account"))

    # 2. Fetch account details
    account_details = Accounts.query.filter_by(id=account_alias).first()
    if not account_details:
        flash("Invalid account selected. Please try again.", "error")
        return redirect(url_for("account.select_account"))

    # 3. Validate API keys and region
    if not all(
        [
            account_details.access_key_id,
            account_details.secret_access_key,
            account_details.default_region_name,
        ]
    ):
        flash(
            "Account configuration is incomplete. Ensure access keys and region are properly set.",
            "error",
        )
        return redirect(url_for("account.select_account"))

    # 4. Define date range
    try:
        START_DATE = (date.today() - timedelta(days=30)).strftime("%Y-%m-%d")
        END_DATE = date.today().strftime("%Y-%m-%d")
    except Exception as e:
        flash(f"Error calculating date range: {str(e)}", "error")
        return redirect(url_for("account.select_account"))

    # 5. Fetch billing data with validation
    try:
        billing_data = fetch_and_cache_billing_data(
            account_details.access_key_id,
            account_details.secret_access_key,
            account_details.default_region_name,
            START_DATE,
            END_DATE,
            granularity="DAILY",
        )
        if not billing_data:
            flash(
                "No billing data available for the selected account and date range.",
                "info",
            )
            billing_data = []
    except Exception as e:
        flash(f"Error fetching billing data: {str(e)}", "error")
        return redirect(url_for("account.select_account"))

    # 6. Prepare CSV data
    try:
        output = [["Date", "Cost (USD)", "Service", "UsageQuantity"]]
        for record in billing_data:
            output.append(
                [
                    record.get("Date", "N/A"),
                    record.get("Cost (USD)", 0),
                    record.get("Service", "N/A"),
                    record.get("UsageQuantity", 0),
                ]
            )
    except Exception as e:
        flash(f"Error preparing CSV data: {str(e)}", "error")
        return redirect(url_for("account.select_account"))

    # 7. Generate CSV response
    try:
        response = Response()
        response.headers["Content-Disposition"] = (
            "attachment; filename=cost_optimization.csv"
        )
        response.headers["Content-Type"] = "text/csv"
        writer = csv.writer(response.stream)
        writer.writerows(output)
        return response
    except Exception as e:
        flash(f"Error generating CSV file: {str(e)}", "error")
        return redirect(url_for("account.select_account"))


@main.route("/cost-optimization/download-pdf")
@login_required
def cost_optimization_pdf():
    """Download PDF for Daily Cost Optimization Data"""
    account_alias = session.get("selected_account")
    if not account_alias:
        flash("No account selected", "error")
        return redirect(url_for("account.select_account"))

    account_details = Accounts.query.filter_by(id=account_alias).first()
    START_DATE = (date.today() - timedelta(days=30)).strftime("%Y-%m-%d")
    END_DATE = date.today().strftime("%Y-%m-%d")

    billing_data = fetch_and_cache_billing_data(
        account_details.access_key_id,
        account_details.secret_access_key,
        account_details.default_region_name,
        START_DATE,
        END_DATE,
        granularity="DAILY",
    )

    # Generate PDF
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setFont("Helvetica", 10)

    # Title with Account Alias and Date Range
    title = f"Account: {account_details.alias} | Date: {START_DATE} to {END_DATE}"
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, 770, title)

    # Table Headers
    pdf.setFont("Helvetica-Bold", 10)
    y_position = 730
    pdf.drawString(50, y_position, "Date")
    pdf.drawString(150, y_position, "Service")
    pdf.drawString(350, y_position, "Usage Quantity")
    pdf.drawString(450, y_position, "Cost (USD)")
    pdf.setFont("Helvetica", 10)

    # Table Data with Pagination
    y_position -= 20
    for record in billing_data:
        if y_position < 50:  # Check for page break
            pdf.showPage()  # Create a new page
            pdf.setFont("Helvetica", 10)
            y_position = 750  # Reset y_position for the new page
            # Re-draw title
            pdf.setFont("Helvetica-Bold", 12)
            pdf.drawString(50, 770, title)
            # Re-draw headers
            pdf.setFont("Helvetica-Bold", 10)
            pdf.drawString(50, y_position, "Date")
            pdf.drawString(150, y_position, "Service")
            pdf.drawString(350, y_position, "Usage Quantity")
            pdf.drawString(450, y_position, "Cost (USD)")
            pdf.setFont("Helvetica", 10)
            y_position -= 20

        # Add the data row
        pdf.drawString(50, y_position, record["Date"])
        pdf.drawString(150, y_position, record["Service"])
        pdf.drawString(350, y_position, f"{record.get('UsageQuantity', 0)}")
        pdf.drawString(450, y_position, f"{record['Cost (USD)']}")
        y_position -= 20

    # Save the PDF
    pdf.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="cost_optimization.pdf",
        mimetype="application/pdf",
    )


@main.route("/api/get_monthly_recommendations", methods=["POST"])
@login_required
def get_monthly_recommendations():
    try:
        # Parse input
        data = request.json
        month_start = data.get("month_start")
        month_end = data.get("month_end")
        services_data = data.get("services_data")

        if not (month_start and month_end and services_data):
            return jsonify({"error": "Invalid or missing input data"}), 400

        # Aggregate cost and usage
        total_monthly_cost = 0
        aggregated_usage = defaultdict(dict)
        aggregated_costs = {}

        for service in services_data:
            service_name = service.get("service_name")
            total_cost = float(service.get("service_cost", 0))
            usage_data = service.get("service_usage", [])
            usage_dates = service.get("usage_dates", [])

            if not (service_name and total_cost and usage_data and usage_dates):
                continue

            total_monthly_cost += total_cost
            aggregated_costs[service_name] = total_cost
            aggregated_usage[service_name] = {
                "usage_quantities": usage_data,
                "usage_dates": usage_dates,
            }

        # Construct enhanced prompt for Claude
        prompt = f"""
        Human:
        You are a senior AWS cost optimization expert working with enterprise cloud accounts. Your task is to analyze detailed monthly billing data and provide professional, easy-to-understand, and actionable cost-saving recommendations.

        The input includes:
        - Billing Period: {month_start} to {month_end}
        - Total Monthly Spend: ${total_monthly_cost:.2f}
        - Breakdown of services with usage patterns and costs:

        """

        for service_name, cost in aggregated_costs.items():
            usage_info = aggregated_usage[service_name]
            prompt += (
                f"  - Service: {service_name}\n"
                f"    - Monthly Cost: ${cost:.2f}\n"
                f"    - Usage Quantities: {usage_info['usage_quantities']}\n"
                f"    - Usage Dates: {usage_info['usage_dates']}\n\n"
            )

        prompt += """
        Assistant:
        Please return a clean, well-structured, and professional summary of recommendations to reduce monthly AWS costs. For each recommendation, include:
        1. Service Name
        2. Optimization Strategy (with simple explanation)
        3. Potential Savings (if estimable)
        4. Additional Notes (if needed)

        Ensure the tone is modern, precise, and suitable for a product UI. Keep the output in plain text, no markdown, no formatting like asterisks or emojis.
        """

        # Call Bedrock with Claude
        bedrock_runtime = boto3.client("bedrock-runtime", region_name="us-east-1")
        response = bedrock_runtime.invoke_model(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            contentType="application/json",
            accept="application/json",
            body=json.dumps(
                {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 1024,
                    "temperature": 0.5,
                    "messages": [{"role": "user", "content": prompt}],
                }
            ),
        )

        result = json.loads(response["body"].read())
        recommendation = result["content"][0]["text"]

        return jsonify(
            {
                "success": True,
                "total_monthly_cost": round(total_monthly_cost, 2),
                "recommendations": recommendation,
            }
        )

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Failed to generate recommendation: {str(e)}"}), 500


# API to start Prowler checks for a specific AWS account
@main.route("/start_checks/<int:account_id>", methods=["POST"])
@login_required
def start_checks(account_id):
    """
    API endpoint to initiate Prowler security checks in a background thread.

    Steps:
    1. Validate if the account exists for the current user.
    2. Ensure the account has necessary AWS credentials and region set.
    3. Start the security checks in a separate thread.
    4. Update the account status to 'pending' in the database.
    5. Return a success response.

    Args:
        account_id (int): ID of the AWS account.

    Returns:
        JSON response with status message.
    """

    # Step 1: Fetch the AWS account details
    account_details = Accounts.query.filter_by(
        id=account_id, account=current_user
    ).first()

    if not account_details:
        return (
            jsonify(
                {
                    "message": "Invalid account selected. Please try again.",
                    "status": "error",
                }
            ),
            400,
        )

    # Step 2: Validate AWS credentials and region
    if not all(
        [
            account_details.access_key_id,
            account_details.secret_access_key,
            account_details.default_region_name,
        ]
    ):
        return (
            jsonify(
                {
                    "message": "Account configuration is incomplete. Ensure access keys and region are properly set.",
                    "status": "error",
                }
            ),
            400,
        )

    # Step 3: Extract necessary AWS credentials
    (
        AWS_ACCESS_KEY,
        AWS_SECRET_KEY,
        AWS_SESSION_TOKEN,
        AWS_REGION,
    ) = _extract_account_credentials(account_details)
    AWS_ALIAS = account_details.alias
    # Determine Prowler checks to run from request body or query parameters.
    data = request.get_json(silent=True) or {}
    checks = data.get("checks")
    if checks is None:
        checks = request.args.getlist("checks")
    if isinstance(checks, str):
        checks = [c.strip() for c in checks.split(",") if c.strip()]
    if not checks:
        checks = []

    user_id = current_user.id
    account_id = account_details.id
    s3_bucket = account_details.s3_bucket

    OUTPUT_DIR = "output"
    output_json_file = os.path.join(
        OUTPUT_DIR, f"{user_id}_{account_id}_report.ocsf.json"
    )

    if os.path.exists(output_json_file):
        os.remove(output_json_file)
    # Step 4: Start the security check process in a background thread
    cancel_event = threading.Event()

    def run_checks_wrapper():
        try:
            run_prowler_checks_concurrently(
                checks,
                AWS_ACCESS_KEY,
                AWS_SECRET_KEY,
                AWS_REGION,
                AWS_ALIAS,
                user_id,
                s3_bucket,
                account_id,
                aws_session_token=AWS_SESSION_TOKEN,
                cancel_event=cancel_event,
            )
        finally:
            with ACTIVE_PROWLER_SCANS_LOCK:
                ACTIVE_PROWLER_SCANS.pop(account_id, None)

    thread = threading.Thread(target=run_checks_wrapper)

    with ACTIVE_PROWLER_SCANS_LOCK:
        existing_job = ACTIVE_PROWLER_SCANS.get(account_id)
        if existing_job and isinstance(existing_job.get("thread"), threading.Thread):
            running_thread = existing_job["thread"]
            if running_thread.is_alive():
                return (
                    jsonify(
                        {
                            "message": "A compliance scan is already running for this account.",
                            "status": "error",
                        }
                    ),
                    409,
                )
        ACTIVE_PROWLER_SCANS[account_id] = {
            "thread": thread,
            "cancel_event": cancel_event,
        }

    # Step 5: Update the database to mark the check as "pending"
    # and store the time the scan was initiated.
    account_details.aws_prowler_check = "pending"
    account_details.aws_prowler_check_date_created = datetime.utcnow()
    db.session.commit()

    thread.start()

    return (
        jsonify(
            {
                "message": "Compliance check will take few minutes, please wait.",
                "status": "success",
            }
        ),
        202,
    )


@main.route("/stop_checks/<int:account_id>", methods=["POST"])
@login_required
def stop_checks(account_id: int):
    """Request cancellation of a running Prowler scan for ``account_id``."""

    account_details = Accounts.query.filter_by(
        id=account_id, account=current_user
    ).first()

    if not account_details:
        return (
            jsonify(
                {
                    "message": "Invalid account selected. Please try again.",
                    "status": "error",
                }
            ),
            400,
        )

    def _mark_cancelled():
        account_details.aws_prowler_check = "cancelled"
        account_details.aws_prowler_check_date_created = None
        account_details.aws_prowler_compliance_report = None
        db.session.commit()

    with ACTIVE_PROWLER_SCANS_LOCK:
        job = ACTIVE_PROWLER_SCANS.get(account_id)

    if not job:
        _mark_cancelled()
        return (
            jsonify(
                {
                    "status": "cancelled",
                    "account_id": account_id,
                    "running": False,
                }
            ),
            200,
        )

    cancel_event = job.get("cancel_event")
    thread = job.get("thread")

    if not isinstance(cancel_event, threading.Event) or not isinstance(
        thread, threading.Thread
    ):
        return (
            jsonify(
                {
                    "message": "Unable to cancel the running scan.",
                    "status": "error",
                }
            ),
            500,
        )

    if not thread.is_alive():
        with ACTIVE_PROWLER_SCANS_LOCK:
            ACTIVE_PROWLER_SCANS.pop(account_id, None)
        _mark_cancelled()
        return (
            jsonify(
                {
                    "status": "cancelled",
                    "account_id": account_id,
                    "running": False,
                }
            ),
            200,
        )

    cancel_event.set()

    thread.join(timeout=10)

    if thread.is_alive():
        return (
            jsonify(
                {
                    "status": "cancelling",
                    "account_id": account_id,
                    "running": True,
                }
            ),
            202,
        )

    with ACTIVE_PROWLER_SCANS_LOCK:
        ACTIVE_PROWLER_SCANS.pop(account_id, None)

    _mark_cancelled()

    return (
        jsonify(
            {
                "status": "cancelled",
                "account_id": account_id,
                "running": False,
            }
        ),
        200,
    )


# API to check if any Prowler check process is running for the current user
@app.route("/check_running_process", methods=["GET"])
@login_required
def check_running_process():
    """Check the current status of a Prowler security check.

    If ``account_id`` is provided as a query parameter, the status for that
    specific account is returned. If ``account_id`` is omitted, the function
    searches for any of the current user's accounts that has a Prowler check
    in a ``pending`` or ``running`` state. If none are found, ``running`` is
    reported as ``False``.

    The endpoint continues to report ``completed`` or ``failed`` states until a
    new scan is initiated.
    """

    account_id = request.args.get("account_id", type=int)
    if account_id is None:
        account_details = (
            Accounts.query.filter(
                Accounts.account == current_user,
                Accounts.aws_prowler_check.in_(["pending", "running"]),
            ).first()
        )
        if not account_details:
            current_app.logger.info(
                "No running prowler check found",
                extra={"user_id": current_user.id},
            )
            return jsonify({"running": False})
    else:
        account_details = Accounts.query.filter_by(
            id=account_id, account=current_user
        ).first()
        if not account_details or not account_details.aws_prowler_check:
            current_app.logger.info(
                "No prowler check found",
                extra={"user_id": current_user.id, "account_id": account_id},
            )
            return jsonify({"running": False, "account_id": account_id})

    account_id = account_details.id

    (
        aws_access_key_id,
        aws_secret_access_key,
        aws_session_token,
        region_name,
    ) = _extract_account_credentials(account_details)

    status = account_details.aws_prowler_check
    current_app.logger.info(
        "Prowler check status fetched",
        extra={
            "account_id": account_details.id,
            "bucket": account_details.s3_bucket,
            "status": status,
        },
    )

    if status == "pending":
        return jsonify(
            {
                "running": True,
                "status": "pending",
                "account_id": account_details.id,
                "start_time": account_details.aws_prowler_check_date_created,
            }
        )

    if status == "running":
        return jsonify(
            {
                "running": True,
                "status": "running",
                "account_id": account_details.id,
                "start_time": account_details.aws_prowler_check_date_created,
            }
        )

    if status == "cancelled":
        return jsonify(
            {
                "running": False,
                "status": "cancelled",
                "account_id": account_details.id,
            }
        )

    if status == "failed":
        current_app.logger.error(
            "Prowler check failed",
            extra={
                "account_id": account_details.id,
                "bucket": account_details.s3_bucket,
                "artifact_key": None,
                "error": account_details.aws_prowler_compliance_report,
            },
        )
        return jsonify(
            {
                "running": False,
                "status": status,
                "error": account_details.aws_prowler_compliance_report,
                "account_id": account_details.id,
            }
        )

    if status in ("completed", "completed_with_findings"):
        try:
            keys = json.loads(account_details.aws_prowler_compliance_report or "{}")
        except json.JSONDecodeError:
            keys = {}

        profile_name = f"{current_user.id}_{account_details.alias}"
        session = _build_account_session(
            profile_name,
            aws_access_key_id,
            aws_secret_access_key,
            region_name,
            aws_session_token,
        )
        s3_client = (
            session.client("s3", region_name=region_name)
            if region_name
            else session.client("s3")
        )
        ensure_account_bucket(
            account_details.id, current_user.id, account_details.s3_bucket
        )

        urls = {}
        for key, value in keys.items():
            if isinstance(value, list):
                urls[key] = [
                    s3_client.generate_presigned_url(
                        "get_object",
                        Params={"Bucket": account_details.s3_bucket, "Key": item},
                    )
                    for item in value
                ]
            else:
                urls[key] = s3_client.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": account_details.s3_bucket, "Key": value},
                )

        current_app.logger.info(
            "Prowler check completed",
            extra={
                "account_id": account_details.id,
                "bucket": account_details.s3_bucket,
                "artifact_keys": keys,
                "status": status,
            },
        )

        # Reflect the exact status stored in the database so the client can
        # differentiate between a clean scan and one with findings.
        response_status = (
            "completed_with_findings"
            if status == "completed_with_findings"
            else "completed"
        )
        return jsonify(
            {
                "running": False,
                "status": response_status,
                "urls": urls,
                "account_id": account_details.id,
            }
        )

    current_app.logger.info(
        "Prowler check in unknown state",
        extra={
            "account_id": account_details.id,
            "bucket": account_details.s3_bucket,
            "status": status,
        },
    )
    return jsonify({"running": False})


# API to check if the compliance report file exists for an account
@main.route("/check_report_file/<int:account_id>", methods=["GET"])
@login_required
def check_report_file(account_id):
    """
    API to check if the AWS compliance report file has been generated.

    Steps:
    1. Validate if the account exists for the current user.
    2. Check for the report file in the account's S3 bucket.
    3. If found, update the account status to 'completed' and return success.
    4. If not found, return 'exists': False.

    Args:
        account_id (int): ID of the AWS account.

    Returns:
        JSON response indicating whether the report file exists.
    """

    # Step 1: Fetch AWS account details
    account_details = Accounts.query.filter_by(
        id=account_id, account=current_user
    ).first()

    if not account_details:
        return (
            jsonify(
                {
                    "message": "Invalid account selected. Please try again.",
                    "status": "error",
                }
            ),
            400,
        )

    base_filename = f"{current_user.id}_{account_details.id}_report.ocsf.json"
    s3_bucket = account_details.s3_bucket

    profile_name = f"{current_user.id}_{account_details.alias}"
    (
        aws_access_key_id,
        aws_secret_access_key,
        aws_session_token,
        region_name,
    ) = _extract_account_credentials(account_details)
    session = _build_account_session(
        profile_name,
        aws_access_key_id,
        aws_secret_access_key,
        region_name,
        aws_session_token,
    )
    s3_client = (
        session.client("s3", region_name=region_name)
        if region_name
        else session.client("s3")
    )
    ensure_account_bucket(account_details.id, current_user.id, s3_bucket)

    report_key: str | None = None

    stored_keys = account_details.aws_prowler_compliance_report or ""
    if stored_keys:
        try:
            parsed_keys = json.loads(stored_keys)
        except json.JSONDecodeError:
            current_app.logger.warning(
                "Failed to parse stored prowler report keys; falling back to S3 lookup",
                extra={"account_id": account_details.id, "bucket": s3_bucket},
            )
        else:
            if isinstance(parsed_keys, dict):
                candidate_key = parsed_keys.get("json_report")
                if isinstance(candidate_key, str):
                    report_key = candidate_key
            else:
                current_app.logger.warning(
                    "Stored prowler report keys have unexpected type %s",
                    type(parsed_keys).__name__,
                    extra={"account_id": account_details.id, "bucket": s3_bucket},
                )

    prefix = f"{S3_REPORT_PREFIX.rstrip('/')}/"

    if not report_key:
        paginator = s3_client.get_paginator("list_objects_v2")
        latest_key: str | None = None
        latest_modified: datetime | None = None
        for page in paginator.paginate(Bucket=s3_bucket, Prefix=prefix):
            for obj in page.get("Contents", []) or []:
                key = obj.get("Key")
                if not key or not key.endswith(base_filename):
                    continue
                last_modified = obj.get("LastModified")
                if isinstance(last_modified, datetime):
                    if latest_modified is None or last_modified > latest_modified:
                        latest_modified = last_modified
                        latest_key = key
                elif latest_key is None:
                    latest_key = key
        if latest_key:
            report_key = latest_key

    if not report_key:
        report_key = f"{prefix}{base_filename}"

    try:
        s3_client.head_object(Bucket=s3_bucket, Key=report_key)
        account_details.aws_prowler_check = "completed"
        # Preserve existing report metadata; this field may store JSON details
        # about generated reports and should not be overwritten here.
        account_details.aws_prowler_check_date_created = None
        db.session.commit()
        return jsonify({"exists": True})
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code not in ("404", "NoSuchKey"):
            # For other errors, log or handle as needed
            pass
        return jsonify({"exists": False})


@main.route("/api/accounts/<int:account_id>", methods=["GET", "PUT"])
@login_required
def api_account(account_id):
    """
    Retrieve or update AWS account details.

    GET: Return JSON with alias, access_key_id, and default_region_name.
    PUT: Update alias, access_key_id, default_region_name, and optionally secret_access_key.
    """
    account = Accounts.query.filter_by(id=account_id).first()
    if not account:
        return jsonify({"error": "Account not found"}), 404

    if request.method == "GET":
        return jsonify(
            {
                "alias": account.alias,
                "access_key_id": account.access_key_id,
                "default_region_name": account.default_region_name,
            }
        )

    data = request.get_json() or {}

    alias = data.get("alias")
    access_key_id = data.get("access_key_id")
    default_region_name = data.get("default_region_name")

    if not all([alias, access_key_id, default_region_name]):
        return (
            jsonify(
                {
                    "error": "alias, access_key_id, and default_region_name are required",
                }
            ),
            400,
        )

    account.alias = alias
    account.access_key_id = access_key_id
    account.default_region_name = default_region_name

    secret_access_key = data.get("secret_access_key")
    if secret_access_key is not None:
        secret_access_key = secret_access_key.strip()
        if secret_access_key:
            account.secret_access_key = secret_access_key

    db.session.commit()

    return jsonify({"message": "Account updated successfully"})
