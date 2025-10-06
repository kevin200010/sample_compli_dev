import json
import os

import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

from app import app
from app.accounts.helpers import ensure_account_bucket

# Constant for directory
FINDINGS_DIR = "findings"


def run_securityhub_command(
    email,
    account_alias,
    s3_bucket,
    aws_access_key_id,
    aws_secret_access_key,
    region,
    account_id=None,
    user_id=None,
):
    """
    Execute AWS Security Hub command to get findings and upload the result to S3.

    Parameters:
        email (str): The user's email, used to generate the output filename.
        account_alias (str): The alias of the AWS account.
        s3_bucket (str): The account's S3 bucket where the findings will be uploaded.
        aws_access_key_id (str): AWS access key for the target account.
        aws_secret_access_key (str): AWS secret key for the target account.
        region (str): AWS region to use for the clients.

    Returns:
        str: Status message indicating success or failure.
    """
    # Temporarily remove any AWS profile so explicitly provided
    # credentials are used without interference from cached
    # configuration profiles.
    original_profile = os.environ.pop("AWS_PROFILE", None)

    try:
        # Ensure findings directory exists
        findings_dir_path = os.path.join(app.root_path, FINDINGS_DIR)
        os.makedirs(
            findings_dir_path, exist_ok=True
        )  # Create the directory if it doesn't exist

        # Build the file paths and S3 key
        filename = os.path.join(findings_dir_path, f"{email}~{account_alias}.json")
        s3_file_key = f"{email}~{account_alias}.json"

        # Check if the file already exists, if not, create an empty one
        if not os.path.exists(filename):
            with open(filename, "w") as f:
                f.write("{}")  # Create an empty JSON file with a default structure

        # Create a dedicated session using the provided credentials so that
        # cached profiles or default sessions do not interfere with the run.
        session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region,
        )
        securityhub_client = session.client("securityhub")

        # Retrieve Security Hub findings without hard limits
        findings = []
        next_token = None

        filters = {
            "SeverityLabel": [
                {"Value": "INFORMATIONAL", "Comparison": "NOT_EQUALS"}
            ]
        }

        while True:
            params = {"Filters": filters, "MaxResults": 100}
            if next_token:
                params["NextToken"] = next_token

            response = securityhub_client.get_findings(**params)

            for finding in response["Findings"]:
                findings.append(
                    {
                        "Resource": finding["Resources"][0]["Id"],
                        "Id": finding["Id"],
                        "Title": finding["Title"],
                        "Description": finding.get("Description"),
                        "Severity": finding["Severity"].get("Label"),
                        "AwsAccountId": finding.get("AwsAccountId"),
                        "LastObservedAt": finding.get("LastObservedAt"),
                        "RecommendationUrl": finding["ProductFields"].get(
                            "RecommendationUrl", ""
                        ),
                        "Types": finding.get("Types"),
                        "Details": finding["Resources"][0].get("Details", {}),
                    }
                )

            next_token = response.get("NextToken")
            if not next_token:
                break

        # Save findings to file
        with open(filename, "w") as f:
            json.dump(findings, f, indent=4)

        # Upload the file to S3
        s3_client = session.client("s3")
        if account_id is not None and user_id is not None:
            ensure_account_bucket(account_id, user_id, s3_bucket)
        with open(filename, "rb") as f:
            s3_client.upload_fileobj(f, s3_bucket, s3_file_key)

        # Return success message
        return True, "Security Hub findings retrieved and uploaded to S3 successfully."

    except NoCredentialsError:
        app.logger.error("AWS credentials not found.")
        return False, "AWS credentials not found. Please configure your AWS credentials."

    except PartialCredentialsError:
        app.logger.error("Incomplete AWS credentials detected.")
        return False, "Incomplete AWS credentials. Please verify your AWS configuration."

    except ClientError as e:
        error = e.response.get("Error", {})
        error_code = error.get("Code")
        error_message = error.get("Message", "")
        message_lower = error_message.lower() if isinstance(error_message, str) else ""

        if error_code == "InvalidAccessException" or "security hub is not enabled" in message_lower:
            notice = "Security Hub is not enabled for this account."
            app.logger.info(notice)
            return True, notice

        if error_code == "UnrecognizedClientException":
            app.logger.error("Invalid AWS security token.")
            return False, "Invalid AWS security token. Please authenticate."
        elif error_code == "AccessDeniedException":
            app.logger.error("Access denied for Security Hub operation.")
            return False, "Access denied. Ensure your IAM role has the required permissions."
        else:
            app.logger.error(f"AWS ClientError: {str(e)}")
            return False, f"AWS error: Please verify your AWS configuration"
    except Exception as e:
        # Log and return error message
        app.logger.error(f"Unexpected error: {e}")
        return False, str(e)
    finally:
        # Restore original AWS profile if it existed
        if original_profile is not None:
            os.environ["AWS_PROFILE"] = original_profile

