from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, ValidationError, Regexp
from flask_login import current_user
from app.models.models import Accounts


class AddAccountForm(FlaskForm):
    alias = StringField(
        "",
        validators=[
            DataRequired(),
            Regexp(
                r"^[a-zA-Z0-9_-]+$",
                message="Alias must not contain special characters or spaces. Only letters, numbers, underscores, and hyphens are allowed.",
            ),
        ],
    )
    access_key = StringField("", validators=[DataRequired()])
    secret_key = PasswordField("", validators=[DataRequired()])
    default_region = StringField("", validators=[DataRequired()])
    submit = SubmitField("Add Account")

    def validate_alias(self, alias):
        """
        Custom validator for alias uniqueness.
        Ensures no duplicate aliases are registered.
        """
        # Check if an account with the provided alias already exists
        account = Accounts.query.filter_by(
            account=current_user, alias=alias.data
        ).first()
        if account:
            raise ValidationError(
                "This account alias is already registered. Please use another one."
            )
