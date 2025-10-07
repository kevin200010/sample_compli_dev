import base64
import logging
import os
from functools import lru_cache

from dotenv import load_dotenv
from msal import ConfidentialClientApplication

logger = logging.getLogger(__name__)


def _aws_region():
    return os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")


@lru_cache(maxsize=1)
def _load_client_secret():
    """Return the Microsoft Graph client secret from the safest available source."""

    direct_secret = os.getenv("CLIENT_SECRET")
    if direct_secret:
        return direct_secret

    parameter_name = os.getenv("AZURE_CLIENT_SECRET_PARAMETER")
    if parameter_name:
        try:
            import boto3

            ssm = boto3.client("ssm", region_name=_aws_region())
            response = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
            secret = response.get("Parameter", {}).get("Value")
            if secret:
                logger.info(
                    "Loaded Microsoft Graph client secret from SSM parameter '%s'",
                    parameter_name,
                )
                return secret
        except Exception as exc:  # pragma: no cover - depends on AWS configuration
            logger.warning(
                "Unable to load Microsoft Graph client secret from SSM parameter '%s': %s",
                parameter_name,
                exc,
            )

    secret_id = os.getenv("AZURE_CLIENT_SECRET_SECRET_ID")
    if secret_id:
        try:
            import boto3

            secrets_manager = boto3.client(
                "secretsmanager", region_name=_aws_region()
            )
            response = secrets_manager.get_secret_value(SecretId=secret_id)
            secret = response.get("SecretString")
            if not secret and "SecretBinary" in response:
                secret = base64.b64decode(response["SecretBinary"]).decode("utf-8")
            if secret:
                logger.info(
                    "Loaded Microsoft Graph client secret from Secrets Manager secret '%s'",
                    secret_id,
                )
                return secret
        except Exception as exc:  # pragma: no cover - depends on AWS configuration
            logger.warning(
                "Unable to load Microsoft Graph client secret from Secrets Manager secret '%s': %s",
                secret_id,
                exc,
            )

    return None


class BaseConfig:
    load_dotenv("/home/ec2-user/GMS-AI/app.env")
    """Base configuration (default settings for all environments)"""

    SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True
    CACHE_TYPE = os.getenv("CACHE_TYPE", "simple")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    NAME = "Global Mobility Services"

    # Security headers
    X_FRAME_OPTIONS = "SAMEORIGIN"

    # AWS Profile (default)
    # Avoid forcing a non-existent default profile. If none is provided
    # in the environment, leave it unset so explicit credentials can be
    # used without profile resolution.
    AWS_PROFILE = os.getenv("AWS_PROFILE")

    # OpenAI API Key
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    NOVA_SONIC_MODEL = os.getenv("NOVA_SONIC_MODEL", "gpt-4o-mini")
    NOVA_SONIC_TRANSCRIBE_MODEL = os.getenv(
        "NOVA_SONIC_TRANSCRIBE_MODEL", "whisper-1"
    )
    UI_COLOR = os.getenv("GMS_UI_COLOR")
    GRADIENT_UI_COLOR = os.getenv("GMS_GRADIENT_UI_COLOR")
    LOGO = os.getenv("LOGO")
    FAV_ICON = os.getenv("FAV_ICON")
    BANNER_IMAGE = os.getenv("BANNER_IMAGE")

    # Azure AD and Office 365 credentials (consider moving these to config)
    CLIENT_ID = os.getenv("CLIENT_ID")
    TENANT_ID = os.getenv("TENANT_ID")
    CLIENT_SECRET = _load_client_secret()
    SENDER_EMAIL = (
        os.getenv("SENDER_EMAIL")
        or os.getenv("MAIL_DEFAULT_SENDER")
        or os.getenv("MAIL_USERNAME")
    )

    # Initialize MSAL app at runtime
    @property
    def msal_app(self):
        return ConfidentialClientApplication(
            self.CLIENT_ID,
            client_credential=self.CLIENT_SECRET,
            authority=f"https://login.microsoftonline.com/{self.TENANT_ID}"
        )


class LocalConfig(BaseConfig):
    """Configuration for local development"""

    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SESSION_COOKIE_SECURE = False  # Allow HTTP for local testing
    ENV = "local"
    

class DevConfig(BaseConfig):
    """Configuration for development server"""

    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SESSION_COOKIE_SECURE = False
    ENV = "development"
    

class ProdConfig(BaseConfig):
    """Production environment configuration"""

    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SESSION_COOKIE_SECURE = False  # Enforce HTTPS
    ENV = "production"
    

class DovetailConfig(BaseConfig):
    """Configuration for white-label deployments"""

    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    ENV = "dovetail"
    UI_COLOR = os.getenv("DOVETAIL_UI_COLOR")
    GRADIENT_UI_COLOR = os.getenv("DOVETAIL_GRADIENT_UI_COLOR")
    LOGO = os.getenv("DEV_LOGO")
    FAV_ICON = os.getenv("DEV_FAV_ICON")
    SESSION_COOKIE_SECURE = True  # Enforce HTTPS
    NAME = "Deovtail Biopartner's"
