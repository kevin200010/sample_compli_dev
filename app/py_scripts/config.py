import json
import os
import subprocess
import sys
import importlib.util


def configure_aws(access_key_id, secret_access_key, default_region_name, email_alias):
    """Configure an AWS CLI profile for the given credentials."""
    default_output_format = "json"
    run_configure(
        access_key_id,
        secret_access_key,
        default_region_name,
        default_output_format,
        email_alias,
    )
    return "AWS CLI configured successfully"


def run_configure(
    access_key_id,
    secret_access_key,
    default_region_name,
    default_output_format,
    email_alias="default",
):
    """Run `aws configure set` for the specified profile.

    The command is executed using the same Python interpreter as the web
    application when the ``awscli`` module is available. This ensures the
    virtual environment's dependencies (e.g. ``python-dateutil``) are used
    instead of any system level installation that might be missing them.
    """
    try:
        base_cmd = ["aws"]
        if importlib.util.find_spec("awscli") is not None:
            base_cmd = [sys.executable, "-m", "awscli"]

        commands = [
            base_cmd
            + [
                "configure",
                "set",
                "aws_access_key_id",
                access_key_id,
                "--profile",
                email_alias,
            ],
            base_cmd
            + [
                "configure",
                "set",
                "aws_secret_access_key",
                secret_access_key,
                "--profile",
                email_alias,
            ],
            base_cmd
            + [
                "configure",
                "set",
                "region",
                default_region_name,
                "--profile",
                email_alias,
            ],
            base_cmd
            + [
                "configure",
                "set",
                "output",
                default_output_format,
                "--profile",
                email_alias,
            ],
        ]
        env = os.environ.copy()
        env.pop("AWS_PROFILE", None)

        for cmd in commands:
            result = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            if result.returncode != 0:
                msg = result.stderr.strip() or result.stdout.strip() or str(result.returncode)
                return False, f"An error occurred while configuring AWS CLI: {msg}"
        return True, "AWS CLI configured successfully."
    except FileNotFoundError:
        return False, "AWS CLI not found. Please install awscli."
    except Exception as ex:
        return False, f"Unexpected error occurred: {ex}"


def verify_aws_profile(profile_name):
    """Verify that the AWS profile is valid by calling STS."""
    try:
        env = os.environ.copy()
        env.pop("AWS_PROFILE", None)

        base_cmd = ["aws"]
        if importlib.util.find_spec("awscli") is not None:
            base_cmd = [sys.executable, "-m", "awscli"]

        result = subprocess.run(
            base_cmd + ["sts", "get-caller-identity", "--profile", profile_name],
            capture_output=True,
            text=True,
            check=True,
            env=env,
        )
        data = json.loads(result.stdout)
        return True, data.get("Account", "")
    except FileNotFoundError:
        return False, "AWS CLI not found. Please install awscli."
    except subprocess.CalledProcessError as e:
        return False, e.stderr.strip()
    except json.JSONDecodeError:
        return False, "Invalid response from AWS STS"

