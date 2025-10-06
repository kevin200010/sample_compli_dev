import concurrent.futures
import json
import os
import glob
import gzip
import subprocess
import threading
import traceback
from datetime import datetime
import re
from typing import Optional

import boto3
from flask import current_app

from app.py_scripts.s3Connection import upload_to_s3
from app import app, db
from app.models.models import Accounts
from app.accounts.helpers import ensure_account_bucket

import matplotlib

matplotlib.use("Agg")  # Set the backend to 'Agg' (non-GUI)
import matplotlib.pyplot as plt
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.platypus import Table, TableStyle

# Constants
OUTPUT_DIR = "output"
PROWLER_REPORTS_DIR = "prowler_reports"

# Prefix used for storing compliance reports in S3. Allow overriding via
# environment variable so deployments can customize the location without code
# changes.
S3_REPORT_PREFIX = os.getenv("S3_REPORT_PREFIX", "Prowler/reports/")

# Fonts and Styles
TITLE_FONT = ("Helvetica-Bold", 24)
SECTION_HEADING_FONT = ("Helvetica-Bold", 18)
SUBHEADING_FONT = ("Helvetica-Bold", 12)
BODY_TEXT_FONT = ("Helvetica", 12)
HEADER_FOOTER_FONT = ("Helvetica-Bold", 10)


class ProwlerScanCancelled(Exception):
    """Raised when a running Prowler scan is cancelled by the user."""


def get_logo_path():
    """Return the absolute path to the company logo."""
    return os.path.join(current_app.root_path, "static/images/gms.png")


def _extract_compliance(finding):
    """Return compliance mapping from a finding.

    Compatibility helper to support legacy and new Prowler schemas by
    inspecting ``unmapped.compliance``, top-level ``compliance`` and
    ``ocsf.compliance`` in that order.
    """

    compliance = finding.get("unmapped", {}).get("compliance", {}) or {}
    if not compliance:
        compliance = finding.get("compliance", {}) or {}
    if not compliance:
        compliance = finding.get("ocsf", {}).get("compliance", {}) or {}
    return compliance


def configure_aws_credentials(
    AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_REGION, aws_session_token=None
):
    """Prepare environment variables for AWS credentials.

    Instead of persisting credentials via ``aws configure set`` (which writes to
    the shared configuration on disk), export the required values directly into
    an environment mapping that can be supplied to ``subprocess.run``.  This
    keeps the credentials scoped to the current process tree.
    """

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env["AWS_ACCESS_KEY_ID"] = AWS_ACCESS_KEY
    env["AWS_SECRET_ACCESS_KEY"] = AWS_SECRET_KEY
    env["AWS_REGION"] = AWS_REGION
    env["AWS_DEFAULT_REGION"] = AWS_REGION
    if aws_session_token:
        env["AWS_SESSION_TOKEN"] = aws_session_token
    return env


def run_prowler_check(
    check_id,
    AWS_ALIAS,
    user_id,
    account_id,
    s3_bucket,
    env,
    cancel_event: Optional[threading.Event] = None,
):
    """Run a single Prowler check.

    Parameters
    ----------
    env : dict
        Environment variables containing scoped AWS credentials. These values
        are passed directly to the Prowler subprocess invocation.

    Returns
    -------
    tuple
        ``(report_path, returncode)`` from the Prowler execution. The
        ``returncode`` allows callers to determine whether findings were
        produced (exit code ``3``) or the run was clean (exit code ``0``).

    Raises
    ------
    FileNotFoundError
        If Prowler completes without producing a report file.
    """
    with app.app_context():
        current_app.logger.info(
            "Starting Prowler check",
            extra={"account_id": account_id, "bucket": s3_bucket, "artifact_key": None},
        )
        # Build the Prowler command. If ``check_id`` is provided we scope the run
        # to that specific check; otherwise the full suite is executed by
        # omitting the ``-c`` flag.
        file_prefix = f"{user_id}_{account_id}_report"
        command = ["prowler", "aws"]
        if check_id:
            command.extend(["-c", check_id])
            file_prefix = f"{user_id}_{account_id}_{check_id}_report"
        command.extend(["-M", "json-ocsf", "-F", file_prefix])
        AWS_REGION = env.get("AWS_REGION")

        region_flag = "--region"
        try:
            version_proc = subprocess.run(
                ["prowler", "--version"],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            version_output = (version_proc.stdout or "").strip()
            if version_output:
                current_app.logger.info(
                    f"Detected Prowler version: {version_output}",
                    extra={"account_id": account_id, "bucket": s3_bucket},
                )
                match = re.search(r"(\d+)", version_output)
                if match and int(match.group(1)) < 4:
                    region_flag = "--region"
                elif not match:
                    raise ValueError("Unable to parse Prowler version")
        except Exception as ver_exc:
            current_app.logger.warning(
                f"Failed to determine Prowler version: {ver_exc}",
                extra={"account_id": account_id, "bucket": s3_bucket},
            )
            try:
                help_proc = subprocess.run(
                    ["prowler", "aws", "--help"],
                    capture_output=True,
                    text=True,
                    env=env,
                    check=False,
                )
                if "--regions" not in help_proc.stdout:
                    region_flag = "--region"
            except Exception as help_exc:
                current_app.logger.warning(
                    f"Failed to probe Prowler flags: {help_exc}",
                    extra={"account_id": account_id, "bucket": s3_bucket},
                )

        current_app.logger.info(
            f"Using region flag '{region_flag}' for Prowler scan",
            extra={"account_id": account_id, "bucket": s3_bucket},
        )
        command.extend([region_flag, AWS_REGION])
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
            )

            stdout_parts: list[str] = []
            stderr_parts: list[str] = []

            while True:
                try:
                    stdout, stderr = process.communicate(timeout=1)
                    if stdout:
                        stdout_parts.append(stdout)
                    if stderr:
                        stderr_parts.append(stderr)
                    break
                except subprocess.TimeoutExpired:
                    if cancel_event and cancel_event.is_set():
                        current_app.logger.info(
                            "Cancellation requested for running Prowler scan.",
                            extra={"account_id": account_id, "bucket": s3_bucket},
                        )
                        process.terminate()
                        try:
                            stdout, stderr = process.communicate(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            stdout, stderr = process.communicate()
                        if stdout:
                            stdout_parts.append(stdout)
                        if stderr:
                            stderr_parts.append(stderr)
                        raise ProwlerScanCancelled()
                    continue

            combined_stdout = "".join(stdout_parts)
            combined_stderr = "".join(stderr_parts)

            if combined_stdout:
                current_app.logger.info(
                    f"Command Output: {combined_stdout.strip()}",
                    extra={"account_id": account_id, "bucket": s3_bucket},
                )
            if combined_stderr:
                current_app.logger.error(
                    f"Command Error Output: {combined_stderr.strip()}",
                    extra={"account_id": account_id, "bucket": s3_bucket},
                )

            returncode = process.returncode

            if returncode not in (0, 3):
                raise subprocess.CalledProcessError(
                    returncode,
                    command,
                    output=combined_stdout,
                    stderr=combined_stderr,
                )

            current_app.logger.info(
                "Completed Prowler check",
                extra={"account_id": account_id, "bucket": s3_bucket, "artifact_key": None},
            )
            # Determine the generated report path for this check.  Prowler may
            # output either a plain JSON file or a gzipped version, so handle
            # both cases here.
            output_json_file = os.path.join(OUTPUT_DIR, f"{file_prefix}.ocsf.json")
            if not os.path.exists(output_json_file):
                pattern = os.path.join(OUTPUT_DIR, f"{file_prefix}*")
                matches = glob.glob(pattern)
                expected_prefix = file_prefix.lower().replace(" ", "_")
                for match in matches:
                    base = os.path.basename(match).lower().replace(" ", "_")
                    if not base.startswith(expected_prefix):
                        continue
                    try:
                        if match.endswith(".gz"):
                            with gzip.open(match, "rb") as f_in, open(
                                output_json_file, "wb"
                            ) as f_out:
                                f_out.write(f_in.read())
                        else:
                            os.rename(match, output_json_file)
                        break
                    except OSError as e:
                        current_app.logger.error(
                            f"Error processing report {match}: {e}",
                            extra={"account_id": account_id, "bucket": s3_bucket},
                        )
                if not os.path.exists(output_json_file):
                    raise FileNotFoundError(
                        f"Prowler report not generated for prefix {file_prefix}"
                    )

            return output_json_file, returncode
        except subprocess.CalledProcessError as e:
            current_app.logger.error(
                f"Prowler check failed with exit code {e.returncode}",
                extra={"account_id": account_id, "bucket": s3_bucket},
            )
            if e.stdout:
                current_app.logger.error(
                    f"stdout: {e.stdout}",
                    extra={"account_id": account_id, "bucket": s3_bucket},
                )
            if e.stderr:
                current_app.logger.error(
                    f"stderr: {e.stderr}",
                    extra={"account_id": account_id, "bucket": s3_bucket},
                )
            raise RuntimeError(
                f"Prowler failed: {e.stderr.strip()}"
            ) from e
        except FileNotFoundError as e:
            check_label = check_id or "all"
            message = (
                "Prowler CLI is not installed or not found in PATH. "
                "Install Prowler to run check(s)."
            )
            current_app.logger.error(
                message,
                extra={"account_id": account_id, "bucket": s3_bucket},
            )
            raise RuntimeError(
                f"Prowler check '{check_label}' failed: {message}"
            ) from e
        except Exception as e:
            check_label = check_id or "all"
            current_app.logger.error(
                f"Error running check {check_label}: {str(e)}",
                extra={"account_id": account_id, "bucket": s3_bucket},
            )
            current_app.logger.error(traceback.format_exc())
            raise RuntimeError(
                f"Prowler check '{check_label}' failed: {e}"
            ) from e


def run_prowler_checks_concurrently(
    check_ids,
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    AWS_REGION,
    AWS_ALIAS,
    user_id,
    s3_bucket,
    account_id,
    aws_session_token=None,
    cancel_event: Optional[threading.Event] = None,
):
    """Run multiple Prowler checks concurrently and upload artifacts to S3."""

    with app.app_context():
        report_paths: list[str] = []
        pdf_paths: list[str] = []
        output_json_file: Optional[str] = None
        storage_prefix: Optional[str] = None
        final_status: str = "failed"
        json_key: Optional[str] = None

        account = Accounts.query.get(account_id)
        if account:
            account.aws_prowler_check = "running"
            account.aws_prowler_check_date_created = datetime.utcnow()
            db.session.commit()

        try:
            try:
                current_app.logger.info(
                    "Starting Prowler checks",
                    extra={"account_id": account_id, "bucket": s3_bucket},
                )

                env = configure_aws_credentials(
                    AWS_ACCESS_KEY,
                    AWS_SECRET_KEY,
                    AWS_REGION,
                    aws_session_token=aws_session_token,
                )
                os.makedirs(OUTPUT_DIR, exist_ok=True)
                os.makedirs(PROWLER_REPORTS_DIR, exist_ok=True)

                if cancel_event and cancel_event.is_set():
                    raise ProwlerScanCancelled()

                return_codes: list[int] = []

                if check_ids:
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future_to_check = {
                            executor.submit(
                                run_prowler_check,
                                check_id,
                                AWS_ALIAS,
                                user_id,
                                account_id,
                                s3_bucket,
                                env,
                                cancel_event=cancel_event,
                            ): check_id
                            for check_id in check_ids
                        }
                        for future in concurrent.futures.as_completed(future_to_check):
                            if cancel_event and cancel_event.is_set():
                                raise ProwlerScanCancelled()
                            check_id = future_to_check[future]
                            try:
                                result = future.result()
                            except ProwlerScanCancelled:
                                raise
                            except Exception as exc:
                                current_app.logger.error(
                                    f"Check {check_id} failed: {exc}",
                                    extra={"account_id": account_id, "bucket": s3_bucket},
                                )
                                raise
                            else:
                                if result is None:
                                    raise RuntimeError(
                                        f"Prowler check {check_id} produced no report"
                                    )
                                path, rc = result
                                report_paths.append(path)
                                return_codes.append(rc)
                else:
                    if cancel_event and cancel_event.is_set():
                        raise ProwlerScanCancelled()
                    path, rc = run_prowler_check(
                        None,
                        AWS_ALIAS,
                        user_id,
                        account_id,
                        s3_bucket,
                        env,
                        cancel_event=cancel_event,
                    )
                    report_paths.append(path)
                    return_codes.append(rc)

                if cancel_event and cancel_event.is_set():
                    raise ProwlerScanCancelled()

                if not report_paths or not return_codes:
                    message = "No Prowler reports were generated"
                    current_app.logger.error(
                        message, extra={"account_id": account_id, "bucket": s3_bucket}
                    )
                    raise RuntimeError(message)

                final_status = (
                    "completed_with_findings" if 3 in return_codes else "completed"
                )

                aggregated_data: list[dict] = []
                for path in report_paths:
                    try:
                        with open(path, "r") as f:
                            aggregated_data.extend(json.load(f))
                    except Exception as e:
                        current_app.logger.error(
                            f"Failed to read report {path}: {e}",
                            extra={"account_id": account_id, "bucket": s3_bucket},
                        )

                for finding in aggregated_data:
                    finding["gms_account_id"] = account_id

                output_json_file = os.path.join(
                    OUTPUT_DIR, f"{user_id}_{account_id}_report.ocsf.json"
                )
                with open(output_json_file, "w") as f:
                    json.dump(aggregated_data, f)

                current_app.logger.info(
                    f"Generated aggregated report {output_json_file}",
                    extra={"account_id": account_id, "bucket": s3_bucket},
                )

                if cancel_event and cancel_event.is_set():
                    raise ProwlerScanCancelled()

                storage_prefix = (
                    f"{S3_REPORT_PREFIX.rstrip('/')}/"
                    f"report-{datetime.utcnow():%Y-%m-%d-%H-%M-%S}/"
                )

                _, pdf_paths = generate_reports(
                    output_json_file,
                    PROWLER_REPORTS_DIR,
                    AWS_ALIAS,
                    user_id,
                    storage_prefix=storage_prefix,
                )

                if cancel_event and cancel_event.is_set():
                    raise ProwlerScanCancelled()

            except ProwlerScanCancelled:
                current_app.logger.info(
                    "Prowler checks cancelled",
                    extra={"account_id": account_id, "bucket": s3_bucket},
                )
                account = Accounts.query.get(account_id)
                if account:
                    account.aws_prowler_check = "cancelled"
                    account.aws_prowler_check_date_created = None
                    account.aws_prowler_compliance_report = None
                    db.session.commit()
                return
            except Exception as exc:
                current_app.logger.error(
                    f"Prowler checks failed: {exc}",
                    extra={"account_id": account_id, "bucket": s3_bucket},
                )
                current_app.logger.error(traceback.format_exc())

                account = Accounts.query.get(account_id)
                if account:
                    account.aws_prowler_check = "failed"
                    account.aws_prowler_check_date_created = None
                    account.aws_prowler_compliance_report = str(exc)
                    db.session.commit()
                    current_app.logger.info(
                        "Database updated with failure status",
                        extra={"account_id": account_id, "bucket": s3_bucket},
                    )

                return

            try:
                session = boto3.Session(
                    aws_access_key_id=AWS_ACCESS_KEY,
                    aws_secret_access_key=AWS_SECRET_KEY,
                    region_name=AWS_REGION,
                    aws_session_token=aws_session_token,
                )
                s3_client = session.client("s3")
                prefix = storage_prefix or ""

                keys: dict[str, list[str] | str] = {}
                pdf_keys: list[str] = []

                if cancel_event and cancel_event.is_set():
                    raise ProwlerScanCancelled()

                ensure_account_bucket(account_id, user_id, s3_bucket)

                json_key = upload_to_s3(
                    output_json_file,
                    s3_bucket,
                    f"{prefix}{os.path.basename(output_json_file)}",
                    account_id,
                    user_id,
                    session=session,
                )
                current_app.logger.info(
                    "Uploaded JSON report to S3",
                    extra={
                        "account_id": account_id,
                        "bucket": s3_bucket,
                        "artifact_key": json_key,
                    },
                )

                for pdf_path in pdf_paths:
                    if cancel_event and cancel_event.is_set():
                        raise ProwlerScanCancelled()
                    key = upload_to_s3(
                        pdf_path,
                        s3_bucket,
                        f"{prefix}{os.path.basename(pdf_path)}",
                        account_id,
                        user_id,
                        session=session,
                    )
                    current_app.logger.info(
                        "Uploaded PDF report to S3",
                        extra={
                            "account_id": account_id,
                            "bucket": s3_bucket,
                            "artifact_key": key,
                        },
                    )
                    pdf_keys.append(key)

            except ProwlerScanCancelled:
                current_app.logger.info(
                    "Prowler upload cancelled",
                    extra={"account_id": account_id, "bucket": s3_bucket},
                )
                account = Accounts.query.get(account_id)
                if account:
                    account.aws_prowler_check = "cancelled"
                    account.aws_prowler_check_date_created = None
                    account.aws_prowler_compliance_report = None
                    db.session.commit()
                return
            except Exception as e:
                current_app.logger.error(
                    f"Failed to refresh S3 reports: {e}",
                    extra={"account_id": account_id, "bucket": s3_bucket},
                )

                account = Accounts.query.get(account_id)
                if account:
                    account.aws_prowler_check = "failed"
                    account.aws_prowler_check_date_created = None
                    account.aws_prowler_compliance_report = str(e)
                    db.session.commit()
                    current_app.logger.info(
                        "Database updated with failure status",
                        extra={"account_id": account_id, "bucket": s3_bucket},
                    )

                return

            keys["json_report"] = json_key
            keys["pdf_reports"] = pdf_keys

            account = Accounts.query.get(account_id)
            if account:
                account.aws_prowler_check = final_status
                account.aws_prowler_check_date_created = None
                account.aws_prowler_compliance_report = json.dumps(keys)
                db.session.commit()
                current_app.logger.info(
                    "Database updated",
                    extra={
                        "account_id": account_id,
                        "bucket": s3_bucket,
                        "artifact_keys": keys,
                    },
                )

            presigned_urls = {
                key: s3_client.generate_presigned_url(
                    "get_object", Params={"Bucket": s3_bucket, "Key": key}
                )
                for key in [json_key] + pdf_keys
            }

            current_app.logger.info(
                "Completed Prowler checks",
                extra={"account_id": account_id, "bucket": s3_bucket, "status": final_status},
            )
            return presigned_urls, final_status
        finally:
            for path in report_paths:
                if path and os.path.exists(path):
                    try:
                        os.remove(path)
                    except OSError:
                        current_app.logger.debug("Failed to remove report %s", path)
            if output_json_file and os.path.exists(output_json_file):
                try:
                    os.remove(output_json_file)
                except OSError:
                    current_app.logger.debug(
                        "Failed to remove aggregated report %s", output_json_file
                    )
            for pdf_path in pdf_paths:
                if pdf_path and os.path.exists(pdf_path):
                    try:
                        os.remove(pdf_path)
                    except OSError:
                        current_app.logger.debug(
                            "Failed to remove PDF report %s", pdf_path
                        )


def generate_donut_chart(findings_summary, chart_path):
    """Generate a donut chart for the findings summary."""
    labels = ["Passed", "Failed"]
    sizes = [findings_summary["Passed"], findings_summary["Failed"]]
    colors = ["#4CAF50", "#F44336"]
    explode = (0.1, 0)

    plt.figure(figsize=(5, 5))
    plt.pie(
        sizes,
        labels=labels,
        autopct="%1.1f%%",
        startangle=140,
        colors=colors,
        explode=explode,
        textprops={"fontsize": 12, "color": "black"},
        wedgeprops={"edgecolor": "black", "linewidth": 1.5},
    )
    plt.savefig(chart_path, bbox_inches="tight")
    plt.close()


def add_resource_finding(pdf, y_position, resource_counter, finding):
    # Extract finding details
    resource_id = finding.get("resources", [{}])[0].get("name", "No Resource ID")
    region = finding.get("cloud", {}).get("region", "Unknown")
    title = finding.get("finding_info", {}).get("title", "No Title")
    status_code = finding.get("status_code", "Unknown").upper()
    recommendations = finding.get("remediation", {})

    # Present findings in order: Resource, Region, Check, Status, Recommendation
    pdf.setFont("Helvetica-Bold", 12)
    pdf.setFillColor(colors.HexColor("#085292"))
    resource_text = f"{resource_counter}. Resource ID: {resource_id}"
    pdf.drawString(40, y_position, resource_text)
    y_position -= 15

    pdf.setFont(BODY_TEXT_FONT[0], BODY_TEXT_FONT[1])
    pdf.setFillColor(colors.black)
    region_text = f"● Region: {region}"
    pdf.drawString(60, y_position, region_text)
    y_position -= 15

    # Handle wrapping for the Check title
    check_text = f"● Check: {title}"
    max_width = 500  # Maximum width for text before wrapping
    line_height = 15  # Height between lines
    lines = []
    words = check_text.split()
    current_line = words[0]
    for word in words[1:]:
        test_line = f"{current_line} {word}"
        if pdf.stringWidth(test_line, BODY_TEXT_FONT[0], BODY_TEXT_FONT[1]) < max_width:
            current_line = test_line
        else:
            lines.append(current_line)
            current_line = word
    lines.append(current_line)

    for line in lines:
        pdf.drawString(60, y_position, line)
        y_position -= line_height

    # Color-coded status
    if status_code == "PASS":
        status_color = colors.HexColor("#4CAF50")  # Green for Pass
        status_icon = "✔️"
    elif status_code == "FAIL":
        status_color = colors.HexColor("#F44336")  # Red for Fail
        status_icon = "❌"
    else:
        status_color = colors.HexColor("#FFC107")  # Yellow for Manual
        status_icon = "🕒"

    pdf.setFillColor(status_color)
    status_text = f"● Status: {status_icon} {status_code}"
    pdf.drawString(60, y_position, status_text)
    y_position -= 15

    # Handle wrapping for the Recommendation
    desc = recommendations.get("desc", "No recommendation available")
    references = recommendations.get("references", [])
    recommendation_text = (
        f"● Recommendation: {desc} ({references[0] if references else ''})"
    )

    # Explicitly set the color to black for the recommendation text
    pdf.setFillColor(colors.black)

    lines = []
    words = recommendation_text.split()
    current_line = words[0]
    for word in words[1:]:
        test_line = f"{current_line} {word}"
        if pdf.stringWidth(test_line, BODY_TEXT_FONT[0], BODY_TEXT_FONT[1]) < max_width:
            current_line = test_line
        else:
            lines.append(current_line)
            current_line = word
    lines.append(current_line)

    for line in lines:
        pdf.drawString(60, y_position, line)
        y_position -= line_height

    return y_position - 10


def add_header_footer(pdf, page_num):
    """Add header and footer to the PDF."""
    pdf.setFont(HEADER_FOOTER_FONT[0], HEADER_FOOTER_FONT[1])
    pdf.setFillColor(colors.HexColor("#085292"))
    logo_path = get_logo_path()
    if os.path.exists(logo_path):
        pdf.drawImage(logo_path, 20, 745, width=70, height=35, mask="auto")
    else:
        current_app.logger.warning(f"Logo not found at {logo_path}; skipping embedding")
    pdf.drawString(500, 770, "Compliance Report")
    pdf.line(50, 730, 550, 730)

    pdf.setFont("Helvetica", 9)
    pdf.setFillColor(colors.black)
    pdf.drawString(40, 40, f"Generated on: {datetime.now().strftime('%Y-%m-%d')}")
    pdf.drawCentredString(300, 40, "cloud@gmobility.com | www.gmobility.com")
    pdf.drawRightString(570, 40, f"Page {page_num}")
    pdf.setLineWidth(0.5)
    pdf.setStrokeColor(colors.black)
    pdf.line(40, 55, 570, 55)


def add_title_page(pdf, findings_summary):
    """Add a title page to the PDF."""
    pdf.setFillColor(colors.HexColor("#085292"))
    pdf.rect(0, 730, 620, 70, fill=True)
    pdf.setFillColor(colors.white)
    pdf.setFont(TITLE_FONT[0], TITLE_FONT[1])
    pdf.drawCentredString(300, 750, "AWS Compliance Report 2025")
    pdf.setFillColor(colors.HexColor("#EE751D"))
    pdf.setFont(SUBHEADING_FONT[0], 16)
    pdf.drawCentredString(300, 710, "Compliance Report")
    pdf.setFont(SUBHEADING_FONT[0], SUBHEADING_FONT[1])
    pdf.setFillColor(colors.HexColor("#085292"))
    pdf.drawString(50, 690, "Date of Report:")
    pdf.setFont(BODY_TEXT_FONT[0], BODY_TEXT_FONT[1])
    pdf.setFillColor(colors.black)
    pdf.drawString(170, 690, f"{datetime.now().strftime('%Y-%m-%d')}")
    pdf.setFillColor(colors.HexColor("#085292"))
    pdf.rect(40, 675, 520, 3, fill=True)
    pdf.setFont(SUBHEADING_FONT[0], 16)
    pdf.setFillColor(colors.HexColor("#085292"))
    pdf.drawString(50, 650, "Summary of Findings:")

    table_data = [
        ["Metric", "Value"],
        ["Total Checks", findings_summary["Total Findings"]],
        ["Passed", findings_summary["Passed"]],
        ["Failed", findings_summary["Failed"]],
        [
            "Compliance (%)",
            f"{findings_summary['Passed'] / findings_summary['Total Findings'] * 100:.2f}%",
        ],
    ]

    table = Table(table_data, colWidths=[250, 200])
    table_style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EE751D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 12),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
            ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.black),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]
    )
    table.setStyle(table_style)
    table.wrapOn(pdf, 50, 490)
    table.drawOn(pdf, 50, 550)

    pdf.setFillColor(colors.HexColor("#085292"))
    pdf.rect(40, 540, 520, 3, fill=True)
    pdf.setFont(SUBHEADING_FONT[0], 16)
    pdf.setFillColor(colors.HexColor("#085292"))
    pdf.drawCentredString(140, 500, "Compliance Distribution:")

    donut_chart_path = "compliance_donut_chart.png"
    generate_donut_chart(findings_summary, donut_chart_path)
    if os.path.exists(donut_chart_path):
        pdf.drawImage(donut_chart_path, 130, 150, width=350, height=350)
        os.remove(donut_chart_path)
    else:
        current_app.logger.warning(
            f"Donut chart not found at {donut_chart_path}; skipping embedding"
        )

    pdf.setFillColor(colors.HexColor("#085292"))
    pdf.rect(40, 55, 520, 3, fill=True)


def generate_pdf_report_for_compliance_type(data, compliance_type, output_pdf_path):
    """Generate a PDF report for a specific compliance type."""
    if compliance_type == "CMMC-Level-2":
        filtered_findings = [
            finding
            for finding in data
            if "NIST-800-171-Revision-2"
               in finding.get("unmapped", {}).get("compliance", {})
        ]
    else:
        filtered_findings = [
            finding
            for finding in data
            if compliance_type in finding.get("unmapped", {}).get("compliance", {})
        ]
    if not filtered_findings:
        return

    findings_summary = {
        "Total Findings": len(filtered_findings),
        "Passed": sum(
            1
            for finding in filtered_findings
            if finding.get("status_code", "").upper() == "PASS"
        ),
        "Failed": sum(
            1
            for finding in filtered_findings
            if finding.get("status_code", "").upper() == "FAIL"
        ),
    }

    pdf = canvas.Canvas(output_pdf_path, pagesize=letter)
    pdf.setTitle(f"{compliance_type} Compliance Report")
    add_title_page(pdf, findings_summary)

    findings_by_service = {}
    for finding in filtered_findings:
        service_name = (
            finding.get("resources", [{}])[0]
            .get("group", {})
            .get("name", "Unknown Service")
            .capitalize()
        )
        findings_by_service.setdefault(service_name, []).append(finding)

    page_num = 1
    for service, findings in findings_by_service.items():
        pdf.showPage()
        add_header_footer(pdf, page_num)
        pdf.setFont("Helvetica-Bold", 18)
        pdf.setFillColor(colors.HexColor("#085292"))
        pdf.drawCentredString(300, 740, service.upper())
        pdf.line(50, 730, 550, 730)

        y_position = 700
        resource_counter = 1

        for finding in findings:
            if y_position < 270:
                pdf.showPage()
                page_num += 1
                add_header_footer(pdf, page_num)
                y_position = 700

            y_position = add_resource_finding(
                pdf, y_position, resource_counter, finding
            )
            resource_counter += 1

    pdf.save()


def generate_reports(
    input_file_path,
    output_dir,
    AWS_ALIAS,
    user_id,
    storage_prefix=None,
):
    """Generate separate PDF reports for each compliance type."""
    os.makedirs(output_dir, exist_ok=True)
    with open(input_file_path, "r") as json_file:
        data = json.load(json_file)
    compliance_report = []
    pdf_paths = []
    all_compliance_types = set()
    for finding in data:
        compliance_data = _extract_compliance(finding)
        all_compliance_types.update(compliance_data.keys())

    prefix = (storage_prefix or S3_REPORT_PREFIX).rstrip("/") + "/"

    for compliance_type in all_compliance_types:
        sanitized_name = compliance_type.replace("-", "_")
        if compliance_type == "NIST-800-171-Revision-2":
            output_pdf_path = os.path.join(
                output_dir, f"{user_id}_{AWS_ALIAS}_CMMC_LEVEL_2_Compliance_Report.pdf"
            )
            filtered_findings = [
                finding
                for finding in data
                if compliance_type in _extract_compliance(finding)
            ]
            if not filtered_findings:
                continue
            passed = sum(
                1
                for finding in filtered_findings
                if finding.get("status_code", "").upper() == "PASS"
            )
            failed = sum(
                1
                for finding in filtered_findings
                if finding.get("status_code", "").upper() == "FAIL"
            )
            pdf_filename = (
                f"{user_id}_{AWS_ALIAS}_CMMC_LEVEL_2_Compliance_Report.pdf"
            )
            findings_summary = {
                "finding_name": "CMMC-Level-2",
                "total_findings": len(filtered_findings),
                "passed": passed,
                "failed": failed,
                "pdf": f"{prefix}{pdf_filename}",
                "compliance_percentage": f"{passed / len(filtered_findings) * 100:.2f}%",
            }
            compliance_report.append(findings_summary)

            generate_pdf_report_for_compliance_type(
                data, "CMMC-Level-2", output_pdf_path
            )
            pdf_paths.append(output_pdf_path)

        output_pdf_path = os.path.join(
            output_dir, f"{user_id}_{AWS_ALIAS}_{sanitized_name}_Compliance_Report.pdf"
        )
        filtered_findings = [
            finding
            for finding in data
            if compliance_type in _extract_compliance(finding)
        ]
        if not filtered_findings:
            continue
        passed = sum(
            1
            for finding in filtered_findings
            if finding.get("status_code", "").upper() == "PASS"
        )
        failed = sum(
            1
            for finding in filtered_findings
            if finding.get("status_code", "").upper() == "FAIL"
        )
        pdf_filename = (
            f"{user_id}_{AWS_ALIAS}_{sanitized_name}_Compliance_Report.pdf"
        )
        findings_summary = {
            "finding_name": compliance_type,
            "total_findings": len(filtered_findings),
            "passed": passed,
            "failed": failed,
            "pdf": f"{prefix}{pdf_filename}",
            "compliance_percentage": f"{passed / len(filtered_findings) * 100:.2f}%",
        }
        compliance_report.append(findings_summary)

        generate_pdf_report_for_compliance_type(data, compliance_type, output_pdf_path)
        pdf_paths.append(output_pdf_path)

    return compliance_report, pdf_paths




def generate_reports_data(
    data,
    output_dir,
    AWS_ALIAS,
    user_id,
    storage_prefix=None,
):
    """Generate separate PDF reports for each compliance type.

    Args:
        data (list): Compliance findings loaded from JSON.
        output_dir (str): Directory for generated reports.
        AWS_ALIAS (str): Account alias.
        user_id (str): Current user's ID.
    """
    compliance_report = []
    all_compliance_types = set()

    for finding in data:
        compliance_data = _extract_compliance(finding)
        all_compliance_types.update(compliance_data.keys())

    prefix = (storage_prefix or S3_REPORT_PREFIX).rstrip("/") + "/"

    for compliance_type in all_compliance_types:
        sanitized_name = compliance_type.replace("-", "_")
        filtered_findings = [
            finding for finding in data if compliance_type in _extract_compliance(finding)
        ]
        if not filtered_findings:
            continue
        passed = sum(
            1
            for finding in filtered_findings
            if finding.get("status_code", "").upper() == "PASS"
        )
        failed = sum(
            1
            for finding in filtered_findings
            if finding.get("status_code", "").upper() == "FAIL"
        )
        pdf_filename = f"{user_id}_{AWS_ALIAS}_{sanitized_name}_Compliance_Report.pdf"
        findings_summary = {
            "finding_name": compliance_type,
            "total_findings": len(filtered_findings),
            "passed": passed,
            "failed": failed,
            "pdf": f"{prefix}{pdf_filename}",
            "compliance_percentage": f"{passed / len(filtered_findings) * 100:.2f}%",
        }
        if compliance_type == "NIST-800-171-Revision-2":
            cmmc_pdf = f"{user_id}_{AWS_ALIAS}_CMMC_LEVEL_2_Compliance_Report.pdf"
            compliance_report.append(
                {
                    "finding_name": "CMMC-Level-2",
                    "total_findings": len(filtered_findings),
                    "passed": passed,
                    "failed": failed,
                    "pdf": f"{prefix}{cmmc_pdf}",
                    "compliance_percentage": f"{passed / len(filtered_findings) * 100:.2f}%",
                }
            )
        compliance_report.append(findings_summary)
    return compliance_report

