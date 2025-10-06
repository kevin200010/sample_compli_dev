import datetime
import json
import re
import shlex
import subprocess
from collections import defaultdict

import boto3
from flask import session, jsonify


def pop_session_if_already_exist():
    for key in list(session.keys()):
        if not key.startswith("_"):  # skip keys set by the flask system
            if (
                    key == "selected_account" or key == "compliance_report"
            ):  # skip keys set by the flask system
                pass
            else:
                del session[key]


def fetch_and_cache_billing_data(
        access_key, secret_key, region, start_date, end_date, granularity
):
    """Fetches billing data and caches it in the session."""
    cache_key = f"billing_data_{start_date}_{end_date}_{granularity}"
    if session.get(cache_key):
        return session[cache_key]

    client = boto3.client(
        "ce",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )

    try:
        response = client.get_cost_and_usage(
            TimePeriod={"Start": start_date, "End": end_date},
            Granularity=granularity,
            Metrics=["UnblendedCost", "UsageQuantity"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
        # Process data into structured format
        data = []
        for result in response["ResultsByTime"]:
            date = result["TimePeriod"]["Start"]
            for group in result.get("Groups", []):
                service = group["Keys"][0]
                cost = float(group["Metrics"]["UnblendedCost"]["Amount"])
                usage = group["Metrics"]["UsageQuantity"]["Amount"]
                data.append(
                    {
                        "Date": date,
                        "Service": service,
                        "Cost (USD)": cost,
                        "UsageQuantity": usage,
                    }
                )
        # Cache the data
        session[cache_key] = data
        return data

    except Exception as e:
        print(f"Error fetching billing data: {e}")
        return None


def save_to_json(data, filename):
    """Save the billing data to a JSON file."""
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Billing data saved to {filename}")


def calculate_cost_for_period(data, start_date, end_date):
    """Helper function to calculate cost for a specific period."""
    return sum(
        record["Cost (USD)"]
        for record in data
        if start_date <= record["Date"] < end_date
    )


def get_date_ranges(today):
    """Helper function to calculate date ranges."""
    return {
        "monthly_start": (today.replace(day=1) - datetime.timedelta(days=365)).strftime(
            "%Y-%m-%d"
        ),
        "daily_start": today.replace(day=1).strftime("%Y-%m-%d"),
        "end": today.strftime("%Y-%m-%d"),
        "last_month_start": (
            (today.replace(day=1) - datetime.timedelta(days=1))
            .replace(day=1)
            .strftime("%Y-%m-%d")
        ),
        "last_month_end": today.replace(day=1).strftime("%Y-%m-%d"),
    }


def generate_summary_data(monthly_data, daily_data, date_ranges, today):
    """Helper function to process and summarize billing data."""
    # Monthly cost breakdown
    monthly_cost = defaultdict(float)
    for record in monthly_data:
        record_date = datetime.datetime.strptime(record["Date"], "%Y-%m-%d")
        month_year = record_date.strftime("%b %Y")
        monthly_cost[month_year] += record["Cost (USD)"]

    sorted_months = sorted(
        monthly_cost.keys(), key=lambda x: datetime.datetime.strptime(x, "%b %Y")
    )
    sorted_monthly_costs = [monthly_cost[month] for month in sorted_months]

    # Calculate various costs
    mtd_cost = sum(record["Cost (USD)"] for record in daily_data)
    forecasted_cost = (mtd_cost / today.day) * 30
    last_month_total_cost = calculate_cost_for_period(
        monthly_data, date_ranges["last_month_start"], date_ranges["last_month_end"]
    )
    last_month_same_period_cost = calculate_cost_for_period(
        daily_data, date_ranges["last_month_start"], date_ranges["last_month_end"]
    )

    # Service breakdown
    service_costs = defaultdict(float)
    for record in daily_data:
        service = record.get("Service", "Unknown")
        service_costs[service] += record["Cost (USD)"]
    services_breakdown = [
        {"name": service, "y": round(cost, 2)}
        for service, cost in service_costs.items()
    ]

    # Highest service by cost
    highest_service = max(daily_data, key=lambda x: x["Cost (USD)"], default=None)

    return {
        "data": daily_data,
        "months": sorted_months,
        "monthly_costs": sorted_monthly_costs,
        "mtd_cost": round(mtd_cost, 2),
        "total_cost": round(sum(record["Cost (USD)"] for record in monthly_data), 2),
        "forecasted_cost": round(forecasted_cost, 2),
        "last_month_total_cost": round(last_month_total_cost, 2),
        "last_month_same_period_cost": round(last_month_same_period_cost, 2),
        "services_breakdown": services_breakdown,
        "highest_service": {
            "service": highest_service["Service"] if highest_service else "None",
            "cost": round(highest_service["Cost (USD)"], 2) if highest_service else 0,
        },
    }


def extract_aws_cli_commands(response_message):
    """
    Extracts AWS CLI commands from the GPT response message.

    Args:
        response_message (str): The response message from GPT.

    Returns:
        list: List of extracted AWS CLI commands.
    """
    # Example regex to match AWS CLI commands
    aws_cli_pattern = re.compile(r'aws\s+[^\n]+')
    return aws_cli_pattern.findall(response_message)


def execute_aws_cli(command, json_input=None):
    """
    Executes an AWS CLI command using subprocess and handles JSON input when required.

    Args:
        command (str): AWS CLI command as a string.
        json_input (dict, optional): JSON data to be passed via stdin.

    Returns:
        dict: Command output or error message.
    """
    try:
        # Execute the command using subprocess
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            return jsonify({"status": "success", "output": result.stdout}), 200
        else:
            return jsonify({"status": "error", "message": {"error": result.stderr}}), 400

    except Exception as e:
        return jsonify({"status": "error", "message": {"error": str(e)}}), 500


compliance_logo_links = {
    "AWS-Account-Security-Onboarding": "https://images.seeklogo.com/logo-png/31/1/amazon-web-services-aws-logo-png_seeklogo-319188.png",
    "AWS-Audit-Manager-Control-Tower-Guardrails": "https://images.seeklogo.com/logo-png/31/1/amazon-web-services-aws-logo-png_seeklogo-319188.png",
    "AWS-Foundational-Security-Best-Practices": "https://images.seeklogo.com/logo-png/31/1/amazon-web-services-aws-logo-png_seeklogo-319188.png",
    "AWS-Foundational-Technical-Review": "https://images.seeklogo.com/logo-png/31/1/amazon-web-services-aws-logo-png_seeklogo-319188.png",
    "AWS-Well-Architected-Framework-Reliability-Pillar": "https://images.seeklogo.com/logo-png/31/1/amazon-web-services-aws-logo-png_seeklogo-319188.png",
    "AWS-Well-Architected-Framework-Security-Pillar": "https://images.seeklogo.com/logo-png/31/1/amazon-web-services-aws-logo-png_seeklogo-319188.png",
    "CIS-1.4": "https://store-images.s-microsoft.com/image/apps.49436.72a55272-5485-44ba-8c3a-fd9ef05d4df5.c63533a1-0922-44e1-a54b-b3016e3ccc6e.3ad24c98-a5b2-44e4-a254-bdcacf7025ef",
    "CIS-1.5": "https://store-images.s-microsoft.com/image/apps.49436.72a55272-5485-44ba-8c3a-fd9ef05d4df5.c63533a1-0922-44e1-a54b-b3016e3ccc6e.3ad24c98-a5b2-44e4-a254-bdcacf7025ef",
    "CIS-2.0": "https://store-images.s-microsoft.com/image/apps.49436.72a55272-5485-44ba-8c3a-fd9ef05d4df5.c63533a1-0922-44e1-a54b-b3016e3ccc6e.3ad24c98-a5b2-44e4-a254-bdcacf7025ef",
    "CIS-3.0": "https://store-images.s-microsoft.com/image/apps.49436.72a55272-5485-44ba-8c3a-fd9ef05d4df5.c63533a1-0922-44e1-a54b-b3016e3ccc6e.3ad24c98-a5b2-44e4-a254-bdcacf7025ef",
    "CISA": "https://upload.wikimedia.org/wikipedia/commons/1/1f/CISA_Logo.png",
    "ENS-RD2022": "https://media.zoom.com/images/assets/ens-compliance.png/Zz05NTc4YTM4ZWNhNDExMWVlODczNGQyMjRjNGZkM2QyMw==?t=20250219041009",
    "FedRAMP-Low-Revision-4": "https://www.ttec.com/sites/default/files/2024-07/fedramp-primary-logo.png",
    "FedRAMP-Moderate-Revision-4": "https://www.ttec.com/sites/default/files/2024-07/fedramp-primary-logo.png",
    "FFIEC": "https://www.doxnet.com/Images_Content/Site1/Images/Pages/ffiec-logo.png",
    "GDPR": "https://www.loginradius.com/wp-content/uploads/2019/10/PNG_GDPR-e1672263252689.png",
    "GxP-21-CFR-Part-11": "https://d1.awsstatic.com/security-center/GxPLogoAws.28e64dceec2c123c4c658824498ae6e1b437a977.jpg",
    "GxP-EU-Annex-11": "https://d1.awsstatic.com/security-center/GxPLogoAws.28e64dceec2c123c4c658824498ae6e1b437a977.jpg",
    "HIPAA": "https://banner2.cleanpng.com/20180822/gyv/kisspng-health-care-medicine-patient-primary-healthcare-accuzip-inc-announces-hipaa-compliant-status-pre-1713928295619.webp",
    "ISO-27001-2013": "https://nishajinfosolutions.com/wp-content/uploads/2024/02/one-1-300x300.png",
    "KISA-ISMS-P-2023": "https://alicloud-common.oss-ap-southeast-1.aliyuncs.com/2023/ISMS_logo.jpg",
    "KISA-ISMS-P-2023-Korean": "https://alicloud-common.oss-ap-southeast-1.aliyuncs.com/2023/ISMS_logo.jpg",
    "MITRE-ATTACK": "https://www.acalvio.com/wp-content/uploads/2019/08/mitrefeatureimg3.jpg",
    "NIST-800-171-Revision-2": "https://tesseract.ardalyst.com/wp-content/uploads/2022/12/NIST_600x400-300x200.png",
    "NIST-800-53-Revision-4": "https://tesseract.ardalyst.com/wp-content/uploads/2022/12/NIST_600x400-300x200.png",
    "NIST-800-53-Revision-5": "https://tesseract.ardalyst.com/wp-content/uploads/2022/12/NIST_600x400-300x200.png",
    "NIST-CSF-1.1": "https://tesseract.ardalyst.com/wp-content/uploads/2022/12/NIST_600x400-300x200.png",
    "PCI-3.2.1": "https://eshielditservices.com/wp-content/uploads/2022/12/pci-dss-1-300x238.png",
    "RBI-Cyber-Security-Framework": "https://www.ardentprivacy.ai/assets/img/RBI_act.jpg",
    "SOC-2": "https://cdn.prod.website-files.com/64009032676f244c7bf002fd/678a6d6fc5825e05c17510b8_678a6d497673e6547fd00d40_aicpa-soc-logo-PNG.png",
    "CMMC-LEVEL-2": "https://www.doxnet.com/Images_Content/Site1/Images/Pages/CMMC-Logo.png",
}
