import os
import subprocess
import threading

# Fetching AWS credentials and region from environment variables
gms_access_key_id = os.getenv("gms_access_key_id")
gms_secret_access_key = os.getenv("gms_secret_access_key")
gms_region = os.getenv("gms_region")


def subprocess_script(key_name, key_id):
    """
    Function to run a subprocess command to configure AWS CLI.
    Args:
    key_name (str): The name of the AWS configuration key.
    key_id (str): The value of the AWS configuration key.
    """
    subprocess.run(
        ["aws", "configure", "set", key_name, key_id],
        check=False,
    )


def configure_gms_aws():
    """
    Function to configure AWS CLI using multiple threads.
    """
    try:
        # List of AWS CLI configure commands
        commands = [
            ("aws_access_key_id", gms_access_key_id),
            ("aws_secret_access_key", gms_secret_access_key),
            ("region", gms_region),
            ("output", "json"),
        ]

        threads = []
        # Creating and starting a thread for each command
        for cmd in commands:
            t = threading.Thread(
                target=subprocess_script,
                args=(
                    cmd[0],
                    cmd[1],
                ),
            )
            t.start()
            threads.append(t)

        # Waiting for all threads to complete
        for t in threads:
            t.join()

        print("AWS CLI configured successfully.")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while configuring AWS CLI: {e}")
