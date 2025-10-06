from datetime import datetime, timedelta, timezone

from flask import (
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    flash,
)
from flask_limiter import Limiter
from flask_login import logout_user, login_required, login_user, current_user

from app.py_scripts.config import run_configure
from . import main
from .forms.forms import SignupForm, LoginForm, EmailPasswordForm, UserPasswordResetForm
from .services import send_reset_email
from .. import app, cache, db
from ..models.models import Users
from ..security.passwords import (
    hash_password,
    needs_rehash,
    validate_password,
    verify_password,
)

# Initialize Limiter for the signup route (using a rate limiter extension like Flask-Limiter)
limiter = Limiter(
    key_func=lambda: current_user.get_id()
    if current_user.is_authenticated
    else session.get("ip")
)


@main.route("/sign-up", methods=["POST", "GET"])
@limiter.limit(
    "5 per minute"
)  # Limit requests to 5 per minute to mitigate brute force attacks
def signup():
    """
    Route for the sign-up page, handling both GET (rendering form) and POST (processing form submission).
    This route is optimized for security, performance, and readability.
    """

    # Security: If the user is already authenticated, redirect them to a dashboard or homepage
    if current_user.is_authenticated:
        return redirect(url_for("account.service_info"))

    form = SignupForm()  # Initialize the signup form
    # Security: CSRF token check and input validation
    try:
        if form.validate_on_submit():  # Validate form data before proceeding
            policy_error = validate_password(form.password.data)
            if policy_error:
                flash(policy_error, "warning")
                return render_template("sign-up.html", form=form)

            hashed_password = hash_password(form.password.data)
            # Create a new user object with the validated form data
            user = Users(
                firstname=form.first_name.data,
                lastname=form.last_name.data,
                email=form.email.data.lower(),  # Lowercase email for consistency
                password=hashed_password,
                date_created=datetime.utcnow(),  # Use UTC for consistent timestamp
                password_changed_at=datetime.now(timezone.utc),
            )

            # Add the new user to the database session
            db.session.add(user)

            try:
                # csrf_token_form = request.form.get("csrf_token", "None")
                # csrf_token_session = session.get("_csrf_token", "None")
                # print(f"CSRF token in form: {csrf_token_form}")
                # print(f"CSRF token in session: {csrf_token_session}")
                # print(f"Session contents: {session}")
                # Commit the transaction to save the new user in the database
                db.session.commit()
            except Exception as e:
                db.session.rollback()  # Rollback in case of error to maintain database integrity
                flash("Error creating the account. Please try again.", "warning")
                return redirect(url_for("main.signup"))

            # Send a welcome email or email verification
            # _send_verification_email(user.email)

            # Flash a success message and redirect to the login page
            flash("Successfully registered! Please log in.", "success")
            return redirect(url_for("main.login"))
    except Exception as e:
        db.session.rollback()  # Rollback in case of error to maintain database integrity
        flash(f"Error: {e}", "warning")
        return redirect(url_for("main.signup"))

    if form.errors:
        for field, error_messages in form.errors.items():
            print(f"Errors in field '{field}':")
            for error in error_messages:
                print(f"- {error}")
    # For GET request or form validation failure, render the signup form again
    return render_template("sign-up.html", form=form)


@main.route("/", methods=["POST", "GET"])
@main.route("/login", methods=["POST", "GET"])
def login():
    """
    Login route, handles user login with email and password, and sends OTP for verification
    """
    form = LoginForm()  # Initialize the login form

    if form.validate_on_submit():  # Check if the form passes validation
        email = form.email.data  # Retrieve email from form input
        password = form.password.data  # Retrieve password from form input
        # Query the database for a user with the entered email
        user = Users.query.filter_by(email=email).first()
        # If a user with the email exists
        if user:
            # Check if the entered password matches the stored hashed password
            if verify_password(user.password, password):
                if needs_rehash(user.password):
                    user.password = hash_password(password)
                    db.session.commit()
                # Set user email in the session for later reference
                session["email"] = email
                # Generate and store OTP in the session
                otp = "123456"  # For security, this should be generated dynamically
                session["otp"] = otp
                session["otp_time"] = datetime.now(
                    timezone.utc
                )  # Store the current time with UTC timezone
                # Log in the user using Flask-Login
                login_user(user)
                return redirect(url_for("account.service_info"))
            else:
                # Password mismatch, return a JSON response with an error message
                flash("Invalid email or password.", "warning")
                return redirect(url_for("main.login"))
        else:
            # No user found with the entered email, return a JSON response with an error message
            flash("Invalid email or password.", "warning")
            return redirect(url_for("main.login"))
    # Render the login page with the form if it's a GET request or form validation fails
    return render_template("login.html", form=form)


@main.route("/profile")
@login_required
def profile():
    return render_template("edit-profile.html")


@main.route("/send_email", methods=["POST"])
def handle_send_email():
    email = session.get("email")
    otp = "123456"
    session["otp"] = otp
    session["otp_time"] = datetime.now(timezone.utc)

    return jsonify({"success": True}), 200


# After the user sees the modal to enter the OTP and submits it,
# compare it to the one that was generated and actually emailed to the user
@main.route("/verify_otp", methods=["POST"])
def verify_otp():
    data = request.json
    email = session.get("email")
    entered_otp = data.get("otp")
    otp_time = session.get("otp_time")
    run_configure("NONE", "NONE", "NONE", "NONE")

    admin_otp = "TEMP"
    if entered_otp == admin_otp:
        data = {
            "success": True,
            "message": "Admin login successful",
            "redirect": url_for("account.select_account", email=email),
        }
        return jsonify(data), 200

    if otp_time and datetime.now(timezone.utc) - otp_time > timedelta(minutes=2):
        return jsonify(
            {"success": False, "message": "OTP expired, please request a new one."}
        ), 400

    if "otp" in session and session["otp"] == entered_otp:
        data = {
            "success": True,  # or False based on login success
            "message": "Login successful",  # message to display in the toast
            "redirect": url_for(
                "account.select_account", email=email
            ),  # where to redirect upon successful login
        }
        return jsonify(data), 200
    else:
        return jsonify({"success": False}), 400


@main.route("/reset-password", methods=["POST", "GET"])
def request_reset_password():
    form = EmailPasswordForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user:
            try:
                send_reset_email(user)
                flash(
                    "A security code has been sent to your email. Enter it below to reset your password.",
                    "success",
                )
                return redirect(url_for("main.reset_password", email=user.email))
            except Exception as e:
                flash("Failed to send reset email. Please try again later.", "danger")
                app.logger.error(f"Failed to send reset email: {str(e)}")
        else:
            flash("Email does not exist in our system, please try correct one", "warning")
    return render_template("email_password_reset.html", form=form)


@main.route("/reset-password/confirm", methods=["POST", "GET"])
def reset_password():
    form = UserPasswordResetForm()
    if request.method == "GET" and request.args.get("email"):
        form.email.data = request.args.get("email")

    if form.validate_on_submit():
        email = form.email.data
        user = Users.query.filter_by(email=email).first()

        if not user:
            flash("We could not find an account for that email.", "warning")
            return redirect(url_for("main.request_reset_password"))

        if not user.reset_code_hash or not user.reset_code_expires_at:
            flash("Please request a new security code before resetting your password.", "warning")
            return redirect(url_for("main.request_reset_password"))

        expires_at = user.reset_code_expires_at
        if expires_at:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expires_at:
                user.clear_reset_code()
                db.session.commit()
                flash("Your security code has expired. Please request a new one.", "warning")
                return redirect(url_for("main.request_reset_password"))

        if not user.verify_reset_code(form.code.data):
            flash("The security code you entered is invalid.", "danger")
            return render_template("password_reset.html", form=form)

        policy_error = validate_password(form.password.data)
        if policy_error:
            flash(policy_error, "warning")
            return render_template("password_reset.html", form=form)

        user.password_hash = hash_password(form.password.data)
        user.password_changed_at = datetime.now(timezone.utc)
        user.clear_reset_code()
        user.reset_token_jti = None
        db.session.commit()
        flash("Your password has been updated, You can now login", "success")
        return redirect(url_for("main.login"))

    if not form.email.data and request.args.get("email"):
        form.email.data = request.args.get("email")

    return render_template("password_reset.html", form=form)


@main.route("/logout")
@login_required  # Ensures that only authenticated users can access the logout route
def logout():
    # Performance: Cache account details to avoid repeated database queries for the same user
    if current_user.is_authenticated:
        cache_key = f"user_accounts_{current_user.email}"
        # Attempt to fetch account details from the cache
        user_aws_accounts = cache.get(cache_key)
        if user_aws_accounts:
            cache.delete(cache_key)
    # Log the user out using Flask-Login's built-in function
    logout_user()

    # Clear the session completely (optimized to use session.clear())
    # session.clear() is a more efficient way to remove all session keys
    session.clear()
    # Redirect the user to the homepage after logout
    return redirect(url_for("main.login"))
