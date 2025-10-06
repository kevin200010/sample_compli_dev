from flask import current_app
from app.models.models import Accounts


def ensure_account_bucket(account_id: int, user_id: int, bucket_name: str) -> None:
    """Validate that *bucket_name* matches the stored bucket for the account.

    Logs a warning and raises :class:`PermissionError` if the bucket does not
    belong to the account or the account does not belong to the user.
    """
    account = Accounts.query.filter_by(id=account_id, user_id=user_id).first()
    if not account or account.s3_bucket != bucket_name:
        current_app.logger.warning(
            "Unauthorized S3 bucket access attempt",
            extra={"account_id": account_id, "user_id": user_id, "bucket": bucket_name},
        )
        raise PermissionError("Unauthorized S3 bucket access")
