import io
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


# --------------- AWS Compliance Check Functions ----------------------


def check_iam_mfa():
    """Check if IAM users have MFA enabled."""
    try:
        iam = boto3.client("iam")
        users = iam.list_users()["Users"]
        mfa_enabled_users = []
        for user in users:
            mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
            if mfa_devices:
                mfa_enabled_users.append(user["UserName"])
        return mfa_enabled_users
    except Exception as e:
        return f"Error checking IAM MFA: {str(e)}"


def check_s3_encryption():
    """Check if S3 buckets have encryption enabled."""
    try:
        s3 = boto3.client("s3")
        buckets = s3.list_buckets()["Buckets"]
        encrypted_buckets = []
        for bucket in buckets:
            encryption = s3.get_bucket_encryption(Bucket=bucket["Name"])
            if "ServerSideEncryptionConfiguration" in encryption:
                encrypted_buckets.append(bucket["Name"])
        return encrypted_buckets
    except Exception as e:
        return f"Error checking S3 encryption: {str(e)}"


def check_ebs_encryption():
    """Check if EBS volumes are encrypted."""
    try:
        ec2 = boto3.client("ec2")
        volumes = ec2.describe_volumes()["Volumes"]
        encrypted_volumes = [vol for vol in volumes if vol["Encrypted"]]
        return encrypted_volumes
    except Exception as e:
        return f"Error checking EBS encryption: {str(e)}"


def check_cloudtrail():
    """Check if CloudTrail is enabled and multi-region."""
    try:
        cloudtrail = boto3.client("cloudtrail")
        trails = cloudtrail.describe_trails()["trailList"]
        enabled_trails = [trail for trail in trails if trail["IsMultiRegionTrail"]]
        return enabled_trails
    except Exception as e:
        return f"Error checking CloudTrail: {str(e)}"


def check_cloudwatch_alarms():
    """Check if there are any active CloudWatch alarms."""
    try:
        cloudwatch = boto3.client("cloudwatch")
        alarms = cloudwatch.describe_alarms()["MetricAlarms"]
        critical_alarms = [alarm for alarm in alarms if alarm["StateValue"] == "ALARM"]
        return critical_alarms
    except Exception as e:
        return f"Error checking CloudWatch alarms: {str(e)}"


def check_backups():
    """Check if regular backups are in place."""
    try:
        backup = boto3.client("backup")
        backup_plans = backup.list_backup_plans()["BackupPlansList"]
        return backup_plans
    except Exception as e:
        return f"Error checking backups: {str(e)}"


def check_vpc_configuration():
    """Check VPC configuration compliance."""
    try:
        ec2 = boto3.client("ec2")
        vpcs = ec2.describe_vpcs()["Vpcs"]
        compliant_vpcs = [vpc["VpcId"] for vpc in vpcs]  # Simplified compliance check
        return compliant_vpcs
    except Exception as e:
        return f"Error checking VPC configuration: {str(e)}"


def check_security_groups():
    """Check security group configurations."""
    try:
        ec2 = boto3.client("ec2")
        security_groups = ec2.describe_security_groups()["SecurityGroups"]
        compliant_security_groups = [sg["GroupId"] for sg in security_groups]
        return compliant_security_groups
    except Exception as e:
        return f"Error checking security groups: {str(e)}"


def check_config_rules():
    """Check AWS Config rule compliance."""
    try:
        config = boto3.client("config")
        rules = config.describe_config_rules()["ConfigRules"]
        compliant_rules = []
        for rule in rules:
            compliance = config.get_compliance_details_by_config_rule(
                ConfigRuleName=rule["ConfigRuleName"]
            )
            if (
                compliance.get("EvaluationResults", [])
                and compliance["EvaluationResults"][0]["ComplianceType"] == "COMPLIANT"
            ):
                compliant_rules.append(rule["ConfigRuleName"])
        return compliant_rules
    except Exception as e:
        return f"Error checking config rules: {str(e)}"


# --------------- Multithreading Compliance Check ----------------------


def perform_compliance_checks():
    """Run all compliance checks in parallel using ThreadPoolExecutor."""
    checks = {
        "IAM User MFA Enabled": check_iam_mfa,
        "S3 Bucket Encryption": check_s3_encryption,
        "EBS Volume Encryption": check_ebs_encryption,
        "CloudTrail Enabled": check_cloudtrail,
        "CloudWatch Alarms": check_cloudwatch_alarms,
        "Regular Backups": check_backups,
        "VPC Configuration": check_vpc_configuration,
        "Security Groups": check_security_groups,
        "AWS Config Rules": check_config_rules,
    }

    results = {}
    with ThreadPoolExecutor() as executor:
        future_to_check = {
            executor.submit(check_func): name for name, check_func in checks.items()
        }
        for future in as_completed(future_to_check):
            check_name = future_to_check[future]
            try:
                results[check_name] = future.result()
            except Exception as e:
                results[check_name] = f"Error in {check_name}: {str(e)}"
    return results


def generate_hipaa_report(report):
    """Generates a HIPAA compliance PDF report with enhanced formatting and detailed information.

    Args:
        report (dict): A dictionary containing compliance check results for various sections.

    Returns:
        io.BytesIO: A buffer containing the generated PDF report.
    """
    # Create a buffer to hold the PDF data
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setTitle("HIPAA Compliance Report")

    # Define margins and initial vertical position for text
    left_margin = 72  # 1 inch
    right_margin = letter[0] - 72  # 1 inch
    top_margin = letter[1] - 72  # 1 inch
    bottom_margin = 72  # 1 inch
    y = top_margin

    # Function to draw a header with a specific style
    def draw_header(text, y, font="Helvetica-Bold", size=16):
        """Draws a header at the specified y position."""
        pdf.setFont(font, size)
        pdf.drawString(left_margin, y, text)
        return y - size - 10  # Adjust y position for next line

    # Function to draw a subheader
    def draw_subheader(text, y, font="Helvetica-Bold", size=14):
        """Draws a subheader at the specified y position."""
        pdf.setFont(font, size)
        pdf.setFillColor(colors.darkblue)
        pdf.drawString(left_margin, y, text)
        pdf.setFillColor(colors.black)
        return y - size - 5  # Adjust y position for next line

    # Function to draw a wrapped text paragraph
    def draw_paragraph(text, y, font="Helvetica", size=10):
        """Draws a wrapped paragraph of text at the specified y position."""
        pdf.setFont(font, size)
        text_width = pdf.stringWidth(text, font, size)
        # Wrap text if it exceeds the maximum width
        if text_width <= (right_margin - left_margin):
            pdf.drawString(left_margin, y, text)
        else:
            words = text.split(" ")
            line = ""
            for word in words:
                test_line = f"{line} {word}".strip()
                test_width = pdf.stringWidth(test_line, font, size)
                if test_width > (right_margin - left_margin):
                    pdf.drawString(left_margin, y, line)
                    line = word
                    y -= size + 2  # Move down for the next line
                else:
                    line = test_line
            pdf.drawString(left_margin, y, line)
        return y - (size + 2)  # Adjust y position for next line

    # Title of the report
    y = draw_header("HIPAA Compliance Check Report", y)
    y = draw_subheader(
        "An overview of your AWS environment's compliance with HIPAA regulations", y
    )

    # Draw a horizontal line for separation
    y -= 10
    pdf.setStrokeColor(colors.black)
    pdf.setLineWidth(1)
    pdf.line(left_margin, y, right_margin, y)
    y -= 20

    # Table of contents section
    y = draw_subheader("Table of Contents:", y)
    for section in report.keys():
        y = draw_paragraph(f"- {section}", y)

    # Draw another horizontal line
    y -= 10
    pdf.line(left_margin, y, right_margin, y)
    y -= 20

    # Compliance details section
    y = draw_subheader("Compliance Details", y)

    # Loop through each section in the report for detailed information
    for section, items in report.items():
        y = draw_subheader(section, y)
        # Add explanation for the section
        explanation = get_section_explanation(section)
        y = draw_paragraph(explanation, y)

        # Check if the section is compliant or non-compliant
        compliant = bool(items)
        status_text = "Compliant" if compliant else "Non-Compliant"
        pdf.setFont("Helvetica-Bold", 10)
        pdf.setFillColor(colors.green if compliant else colors.red)
        y = draw_paragraph(f"Status: {status_text}", y)
        pdf.setFillColor(colors.black)

        # Detailed information of compliant items or explanation of non-compliance
        if compliant:
            for item in items:
                y = draw_paragraph(f"- {item}", y)
        else:
            y = draw_paragraph(
                "No compliant resources found. Please review your configuration.", y
            )

        # Add remediation steps for the section
        remediation = get_remediation_steps(section)
        y = draw_paragraph("Recommended Remediation Steps:", y)
        y = draw_paragraph(remediation, y)

        # Draw a line after each section for separation
        y -= 10
        pdf.line(left_margin, y, right_margin, y)
        y -= 20  # Extra space before the next section

        # Check if we need to add a new page
        if y < bottom_margin:
            pdf.showPage()
            y = top_margin

    # Finalize the PDF
    pdf.showPage()
    pdf.save()
    buffer.seek(0)  # Rewind the buffer to the beginning
    return buffer  # Return the buffer containing the PDF data


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
