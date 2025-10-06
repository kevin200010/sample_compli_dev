import os

from dotenv import load_dotenv

from .base_config import LocalConfig, DevConfig, ProdConfig, DovetailConfig


def get_config():
    load_dotenv("/home/ec2-user/GMS-AI/app.env")
    env = os.getenv("FLASK_ENV", "local")  # Default to local if not set
    if env == "local":
        return LocalConfig
    elif env == "development":
        return DevConfig
    elif env == "production":
        return ProdConfig
    elif env == "dovetail":
        return DovetailConfig
    else:
        raise ValueError(f"Unknown environment: {env}")
