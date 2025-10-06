import os
import random
import string

import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

AWS_REGION = os.getenv("AWS_REGION")
SENDER = os.getenv("SENDER_EMAIL")


def generate_otp():
    return "".join(random.choices(string.digits, k=6))


def send_email(recipient_email, otp):
    subject = "Your Verification Code"
    body_text = f"Your verification code is: {otp}"
    charset = "UTF-8"
    ses_client = boto3.client("ses", region_name=AWS_REGION)
    try:
        response = ses_client.send_email(
            Destination={
                "ToAddresses": [recipient_email],
            },
            Message={
                "Body": {
                    "Text": {
                        "Charset": charset,
                        "Data": body_text,
                    },
                },
                "Subject": {
                    "Charset": charset,
                    "Data": subject,
                },
            },
            Source=SENDER,
        )
        return True
    except (NoCredentialsError, PartialCredentialsError) as e:
        print(f"Credentials error: {str(e)}")
        return False
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        return False
