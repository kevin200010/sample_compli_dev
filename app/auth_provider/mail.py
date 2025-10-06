import requests
from flask import current_app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

from app.models.models import Users  # Import your User model

GRAPH_API_BASE_URL = "https://graph.microsoft.com/v1.0"


class Mail:
    def __init__(self, app=None):
        """
        Initialize the Mail class with Flask app settings.
        """
        self.secret_key = None  # Will be set via init_app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Initialize Mail settings from Flask config.
        """
        self.secret_key = app.config.get("SECRET_KEY")
        if not self.secret_key:
            raise ValueError("SECRET_KEY is missing in app configuration.")

    def get_reset_token(self, email, expire_sec=1800):
        """
        Generate a secure reset token for authentication.
        """
        s = Serializer(self.secret_key, expire_sec)
        return s.dumps({"users": email}).decode("utf-8")

    @staticmethod
    def verify_reset_token(token):
        """
        Verify a token and return the associated user if valid.
        """
        s = Serializer(current_app.config["SECRET_KEY"])
        try:
            users_email = s.loads(token)["users"]
        except:
            return None
        return Users.query.filter_by(email=users_email).first()

    def send_message(self, sender, recipients, subject, body):
        """
        Send an email using Microsoft Graph API.

        Parameters:
            sender (str): Sender's email address.
            recipients (list): List of recipient email addresses.
            subject (str): Email subject.
            body (str): Email body.

        Returns:
            bool: True if email is sent successfully, False otherwise.
        """
        if not self.secret_key:
            current_app.logger.error("SECRET_KEY is not configured.")
            return False

        # Generate token for authentication
        token = self.get_reset_token(sender)

        # Verify token before sending email
        user = self.verify_reset_token(token)
        if not user:
            current_app.logger.error("Invalid or expired token.")
            return False

        url = f"{GRAPH_API_BASE_URL}/users/{sender}/sendMail"

        email_data = {
            "message": {
                "subject": subject,
                "body": {"contentType": "Text", "content": body},
                "toRecipients": [{"emailAddress": {"address": email}} for email in recipients]
            }
        }

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        response = requests.post(url, headers=headers, json=email_data)

        if response.status_code == 202:
            current_app.logger.info("Email sent successfully.")
            return True
        else:
            current_app.logger.error(f"Failed to send email: {response.text}")
            return False
