import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from app.py_scripts.hipaa import (
    check_iam_mfa,
    check_cloudwatch_alarms,
    check_backups,
    check_vpc_configuration,
    check_config_rules,
    check_security_groups,
    check_ebs_encryption,
    check_cloudtrail,
    check_s3_encryption,
)


def perform_compliance_check():
    failed_checks = {}

    try:
        iam_mfa = check_iam_mfa()

        if not iam_mfa:
            failed_checks["IAM User MFA Enabled"] = "MFA not enabled for all users"
    except Exception as e:
        failed_checks["IAM User MFA Enabled"] = f"Error checking IAM MFA: {str(e)}"

    try:
        s3_encryption = check_s3_encryption()

        if not s3_encryption:
            failed_checks["S3 Bucket Encryption"] = (
                "Server-side encryption not enabled for all buckets"
            )
    except Exception as e:
        failed_checks["S3 Bucket Encryption"] = (
            f"Error checking S3 encryption: {str(e)}"
        )

    try:
        ebs_encryption = check_ebs_encryption()

        if not ebs_encryption:
            failed_checks["EBS Volume Encryption"] = (
                "Encryption not enabled for all EBS volumes"
            )
    except Exception as e:
        failed_checks["EBS Volume Encryption"] = (
            f"Error checking EBS encryption: {str(e)}"
        )

    try:
        cloudtrail = check_cloudtrail()

        if not cloudtrail:
            failed_checks["CloudTrail Enabled"] = (
                "CloudTrail not enabled in all regions"
            )
    except Exception as e:
        failed_checks["CloudTrail Enabled"] = f"Error checking CloudTrail: {str(e)}"

    try:
        cloudwatch_alarms = check_cloudwatch_alarms()

        if not cloudwatch_alarms:
            failed_checks["CloudWatch Alarms"] = (
                "Critical CloudWatch alarms are not in place"
            )
    except Exception as e:
        failed_checks["CloudWatch Alarms"] = (
            f"Error checking CloudWatch alarms: {str(e)}"
        )

    try:
        backups = check_backups()

        if not backups:
            failed_checks["Regular Backups"] = (
                "Regular backups are not scheduled for all critical resources"
            )
    except Exception as e:
        failed_checks["Regular Backups"] = f"Error checking backups: {str(e)}"

    try:
        vpc_configuration = check_vpc_configuration()

        if not vpc_configuration:
            failed_checks["VPC Configuration"] = (
                "VPCs are not configured correctly with appropriate subnetting, routing, and security groups"
            )
    except Exception as e:
        failed_checks["VPC Configuration"] = (
            f"Error checking VPC configuration: {str(e)}"
        )

    try:
        security_groups = check_security_groups()

        if not security_groups:
            failed_checks["Security Groups"] = "Security groups are overly permissive"
    except Exception as e:
        failed_checks["Security Groups"] = f"Error checking security groups: {str(e)}"

    try:
        config_rules = check_config_rules()

        if not config_rules:
            failed_checks["AWS Config Rules"] = (
                "AWS Config rules are not compliant with PCI standards"
            )
    except Exception as e:
        failed_checks["AWS Config Rules"] = f"Error checking AWS Config rules: {str(e)}"

    return failed_checks


def generate_pdf_report(compliance_results):
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setTitle("PCI Compliance Failures Report")

    width, height = letter

    # Title
    pdf.setFont("Helvetica-Bold", 24)
    pdf.setFillColor(colors.blue)
    pdf.drawString(72, height - 72, "PCI Compliance Check Report")

    # Add summary statement
    pdf.setFont("Helvetica", 12)
    pdf.setFillColor(colors.black)
    summary_text = (
        "This report provides a summary of the compliance checks performed in your AWS environment against "
        "PCI standards."
    )
    y = height - 90  # Adjusting y position for the summary
    y = draw_wrapped_text(pdf, summary_text, 72, y, width - 144)

    # Add a line separator
    pdf.setStrokeColor(colors.grey)
    pdf.setLineWidth(1)
    pdf.line(72, y, width - 72, y)

    # Starting Y position for compliance results
    y -= 20  # Adjust Y position for the results

    # Iterate through the compliance results and add them to the PDF
    for section, result in compliance_results.items():
        # Draw section header with color
        pdf.setFont("Helvetica-Bold", 16)
        pdf.setFillColor(colors.darkblue)
        pdf.drawString(72, y, section)
        y -= 20  # Space after section title

        # Reset fill color for the content
        pdf.setFillColor(colors.black)
        pdf.setFont("Helvetica", 12)

        # Draw result with compliance status
        compliance_status = "Compliant" if result else "Non-Compliant"
        pdf.drawString(
            72, y, f"Status: {compliance_status}"
        )  # Changed "Compliance Status" to "Status"
        y -= 15  # Space after compliance status

        # Draw results based on their type
        if isinstance(result, str):
            y = draw_wrapped_text(pdf, f"{result}", 72, y, width - 144)
        elif isinstance(result, list):
            result_strings = [str(item) for item in result]
            y = draw_wrapped_text(
                pdf, f"{', '.join(result_strings)}", 72, y, width - 144
            )
        elif isinstance(result, dict):
            pdf.drawString(72, y, "Result: Issues found:")
            y -= 15  # Space after "Issues found"
            # Draw each issue in a structured format
            for key, value in result.items():
                pdf.drawString(82, y, f"• {key}: {value}")  # Bulleted list for issues
                y -= 15  # Space after each issue
        else:
            pdf.drawString(72, y, "Result: Unknown format")
            y -= 15  # Space for unknown format message

        y -= 5  # Add a little space before explanation

        # Draw explanation
        explanation = get_section_explanation(section)
        y = draw_wrapped_text(pdf, f"Explanation: {explanation}", 72, y, width - 144)

        y -= 5  # Add a little space before remediation

        # Draw remediation steps
        remediation_steps = get_remediation_steps(section)
        y = draw_wrapped_text(
            pdf, f"Remediation: {remediation_steps}", 72, y, width - 144
        )

        # Add some space between sections
        y -= 20  # Space before the next section

        # Check if there's enough space for the next section, create a new page if needed
        if y < 72:
            pdf.showPage()
            y = height - 72  # Reset Y position for new page

    # Add footer with page number
    pdf.setFont("Helvetica", 10)
    pdf.drawString(72, 30, "Page 1")

    # Save the PDF
    pdf.save()

    buffer.seek(0)
    return buffer


def format_dict_result(result_dict):
    """Formats the dictionary result into a string for the PDF."""
    formatted_result = []
    for key, value in result_dict.items():
        if isinstance(value, list):
            formatted_result.append(f"{key}: {', '.join(str(v) for v in value)}")
        elif isinstance(value, datetime):
            formatted_result.append(f"{key}: {value.isoformat()}")
        else:
            formatted_result.append(f"{key}: {value}")
    return "\n".join(formatted_result)


def draw_wrapped_text(pdf, text, x, y, max_width):
    """Draws wrapped text in the PDF with proper formatting."""
    text_object = pdf.beginText(x, y)
    text_object.setFont("Helvetica", 12)

    for line in text.splitlines():
        for word in line.split():
            # Check if the next word fits within the maximum width
            if (
                text_object.getX() + pdf.stringWidth(word + " ", "Helvetica", 12)
                > x + max_width
            ):
                pdf.drawText(text_object)
                text_object = pdf.beginText(
                    x, text_object.getY() - 14
                )  # Move down for the new line
                text_object.setFont("Helvetica", 12)
            text_object.textOut(word + " ")
        # After finishing a line, draw the current line
        pdf.drawText(text_object)
        text_object = pdf.beginText(
            x, text_object.getY() - 14
        )  # Move down for the new line

    return text_object.getY()


def get_section_explanation(section):
    explanations = {
        "IAM User MFA Enabled": "Multi-Factor Authentication (MFA) ensures that users are required to provide multiple forms of identification before accessing resources. Not enabling MFA increases the risk of unauthorized access.",
        "S3 Bucket Encryption": "S3 bucket encryption protects data at rest by encrypting it on the server side. Unencrypted S3 buckets may expose sensitive data to unauthorized access.",
        "EBS Volume Encryption": "EBS volume encryption secures data at rest within Amazon Elastic Block Store. Non-encrypted volumes can lead to data breaches if unauthorized access occurs.",
        "CloudTrail Enabled": "AWS CloudTrail enables governance, compliance, and operational and risk auditing. Without CloudTrail, there is no way to track account activity.",
        "CloudWatch Alarms": "CloudWatch alarms monitor AWS resources and trigger actions when certain thresholds are reached. Not having alarms set up can lead to unmonitored critical issues.",
        "Regular Backups": "Regular backups ensure that your data can be restored in case of failure or corruption. Not having regular backups can result in data loss.",
        "VPC Configuration": "Proper VPC configuration ensures that your network is secure and properly segmented. Misconfigurations can lead to network vulnerabilities.",
        "Security Groups": "Security groups act as virtual firewalls to control inbound and outbound traffic. Improperly configured security groups can expose your resources to unauthorized access.",
        "AWS Config Rules": "AWS Config rules evaluate the configuration settings of your AWS resources. Non-compliant rules may indicate misconfigured resources.",
    }
    return explanations.get(section, "No explanation available.")


def get_remediation_steps(section):
    remediation = {
        "IAM User MFA Enabled": "Enable MFA for all IAM users via the IAM console or CLI.",
        "S3 Bucket Encryption": "Enable server-side encryption for all S3 buckets. Consider using AWS KMS for managing encryption keys.",
        "EBS Volume Encryption": "Ensure that all EBS volumes are encrypted. Enable default EBS encryption in your AWS account settings.",
        "CloudTrail Enabled": "Enable AWS CloudTrail for all regions and ensure logs are stored in a secure, encrypted S3 bucket.",
        "CloudWatch Alarms": "Set up CloudWatch alarms to monitor critical resources and send notifications when thresholds are breached.",
        "Regular Backups": "Implement regular backup schedules for all critical data and test restore procedures periodically.",
        "VPC Configuration": "Review VPC settings for best practices such as enabling flow logs, using private subnets, and securing endpoints.",
        "Security Groups": "Regularly review and update security group rules to ensure they follow the principle of least privilege.",
        "AWS Config Rules": "Review AWS Config rules and ensure they cover all critical configurations. Remediate any non-compliant resources.",
    }
    return remediation.get(section, "No remediation steps available.")
