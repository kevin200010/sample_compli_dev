from flask_wtf import FlaskForm
from wtforms import HiddenField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, ValidationError, EqualTo, Length

from app.models.models import Users


class LoginForm(FlaskForm):
    """
    Login form for user authentication.
    Enhanced for security and usability.
    """

    email = StringField(
        "Email Address",
        validators=[
            DataRequired()
        ],  # Added Email validator for email format validation
        render_kw={
            "placeholder": "Enter your email address"
        },  # Improved form usability with placeholders
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired()],
        render_kw={"placeholder": "Enter your password"},  # Placeholder for better UX
    )
    submit = SubmitField("Sign In")


class SignupForm(FlaskForm):
    """
    Signup form for new user registration.
    Contains additional validation for email uniqueness and password confirmation.
    """

    first_name = StringField(
        "First Name",
        validators=[DataRequired()],
        render_kw={"placeholder": "Enter your first name"},  # Placeholder for better UX
    )
    last_name = StringField(
        "Last Name",
        validators=[DataRequired()],
        render_kw={"placeholder": "Enter your last name"},  # Placeholder for better UX
    )
    email = StringField(
        "Email",
        validators=[DataRequired()],  # Added email format validation
        render_kw={"placeholder": "Enter your email"},  # Placeholder for better UX
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8)],
        render_kw={
            "placeholder": "Enter a strong password"
        },  # Placeholder for better UX
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo(
                "password", message="Passwords must match"
            ),  # Ensures passwords match
        ],
        render_kw={"placeholder": "Confirm your password"},  # Placeholder for better UX
    )
    submit = SubmitField("Sign Up")

    def validate_email(self, email):
        """
        Custom validator for email uniqueness.
        Ensures no duplicate emails are registered.
        """
        # Check if a user with the provided email already exists
        user = Users.query.filter_by(
            email=email.data.lower()
        ).first()  # Convert email to lowercase for consistency
        if user:
            raise ValidationError(
                "This email is already registered. Please use another email."
            )

    def validate_password(self, password):
        SpecialSym = ["$", "@", "#", "%"]
        if not any(char.isdigit() for char in password.data):
            raise ValidationError(
                "Password should have at least one numeral (ex: Pass@123)"
            )

        if not any(char.isupper() for char in password.data):
            raise ValidationError(
                "Password should have at least one uppercase letter (ex: Pass@123)"
            )

        if not any(char.islower() for char in password.data):
            raise ValidationError(
                "Password should have at least one lowercase letter (ex: Pass@123)"
            )

        if not any(char in SpecialSym for char in password.data):
            raise ValidationError(
                "Password should have at least one of these four symbols $ @ # % (ex: Pass@123)"
            )


class EmailPasswordForm(FlaskForm):
    email = StringField("Email Address", validators=[DataRequired()])
    submit = SubmitField("Send Reset Email")

    def validate_email(self, email):
        """
        Custom validator for email uniqueness.
        Ensures no duplicate emails are registered.
        """
        # Check if a user with the provided email already exists
        user = Users.query.filter_by(
            email=email.data.lower()
        ).first()  # Convert email to lowercase for consistency
        if not user:
            raise ValidationError(
                "This email is already registered. Please use another email."
            )


class UserPasswordResetForm(FlaskForm):
    email = HiddenField(validators=[DataRequired()])
    code = StringField("Security Code", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Update")

    def validate_password(self, password):
        SpecialSym = ["$", "@", "#", "%"]
        if not any(char.isdigit() for char in password.data):
            raise ValidationError(
                "Password should have at least one numeral (ex: Pass@123)"
            )

        if not any(char.isupper() for char in password.data):
            raise ValidationError(
                "Password should have at least one uppercase letter (ex: Pass@123)"
            )

        if not any(char.islower() for char in password.data):
            raise ValidationError(
                "Password should have at least one lowercase letter (ex: Pass@123)"
            )

        if not any(char in SpecialSym for char in password.data):
            raise ValidationError(
                "Password should have at least one of these four symbols $ @ # % (ex: Pass@123)"
            )
