from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import current_user, login_user, logout_user, login_required
from . import db, env, secret_key, limiter
from .models import User, PasswordReset
from werkzeug.security import generate_password_hash, check_password_hash
from .utils import is_bot, password_meets_security_requirements
from itsdangerous import URLSafeTimedSerializer
import resend
from datetime import datetime
from urllib import parse
from uuid import uuid4
from .config import PASSWORD_RESET_TIMEOUT
from markupsafe import Markup
import pyotp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import logging


auth = Blueprint("auth", __name__)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def send_otp_email(email, otp):
    sender_email = env.get('EMAIL_ADDRESS')
    sender_password = env.get('EMAIL_PASSWORD')
    
    logger.debug(f"Attempting to send OTP email to {email}")
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = "Your OTP Verification Code"
    
    body = f"""
    Your OTP verification code is: {otp}
    
    This code will expire in 5 minutes.
    
    If you didn't request this code, please ignore this email.
    """
    
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        logger.debug("Connected to SMTP server")
        server.login(sender_email, sender_password)
        logger.debug("Logged in to SMTP server")
        text = msg.as_string()
        server.sendmail(sender_email, email, text)
        logger.debug("Email sent successfully")
        server.quit()
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP: {str(e)}")
        return False

def generate_otp():
    otp = pyotp.TOTP(pyotp.random_base32(), interval=300).now()  # 5 minutes expiry
    logger.debug(f"Generated OTP: {otp}")
    return otp


@auth.route("/login", methods=["POST"])
@limiter.limit("5/minute")
def login_post():
    email = request.form.get("email")
    password = request.form.get("password")
    remember = True if request.form.get("remember") else False
    
    # Check CAPTCHA first before proceeding
    if is_bot(request):
        flash("Please complete the CAPTCHA")
        return redirect(url_for("auth.login_get"))
    
    user = User.query.filter_by(email=email).first()

    if user is None:
        flash("User does not exist, sign up instead?")
        return redirect(url_for("auth.signup_get"))

    if not check_password_hash(user.password, password):
        flash("Incorrect login credentials")
        return redirect(url_for("auth.login_get"))

    if not user.email_verified:
        flash("Please verify your email first")
        return redirect(url_for("auth.login_get"))

    login_user(user, remember=remember)
    return redirect(url_for("main.profile"))


@auth.route("/login", methods=["GET"])
def login_get():
    return render_template("login.html", captcha_sitekey=env['RECAPTCHA_PUBLIC_KEY'])


@auth.route("/confirm/<token>")
@login_required
def confirm_email(token):
    if current_user.email_verified:
        flash("Account is already confirmed")
        return redirect(url_for("main.profile"))

    email = confirm_token(token)
    user = User.query.filter_by(email=current_user.email).first()

    if user.email == email:
        user.email_verified = True
        db.session.commit()

    return redirect(url_for("main.profile"))


@auth.route("/signup", methods=["POST"])
@limiter.limit("5/minute")
def signup_post():
    email = request.form.get("email")
    username = request.form.get("username")
    password = request.form.get("password")
    phone_no = request.form.get("phone-no")

    user = User.query.filter_by(email=email).first()

    if user:
        flash(
            Markup(
                'This email already has an account!  Go to <a href="/login">login page</a>.'
            )
        )
        return redirect(url_for("auth.signup_get"))

    if not password_meets_security_requirements(password):
        flash(Markup('Password is not strong enough!! See <a href="/password_policy">our password policy</a> for more info'))
        return redirect(url_for("auth.signup_get"))

    if is_bot(request):
        flash("Captcha failed")
        return redirect(url_for("auth.signup_get"))

    # Generate OTP
    otp = generate_otp()
    
    new_usr = User(
        email=email, 
        username=username, 
        password=generate_password_hash(password), 
        phone_number=phone_no,
        email_verified=False,  # Set to False until OTP verification
        otp=otp,
        otp_created_at=datetime.utcnow()
    )

    # Send OTP email
    if send_otp_email(email, otp):
        db.session.add(new_usr)
        db.session.commit()
        return redirect(url_for("auth.verify_signup_otp", email=email))
    else:
        flash("Failed to send verification email. Please try again.")
        return redirect(url_for("auth.signup_get"))


def generate_token(email):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(email, salt=env["SECURITY_PASSWORD_SALT"])


def confirm_token(token, expiration=1800):
    serializer = URLSafeTimedSerializer(secret_key)
    try:
        email = serializer.loads(
            token, salt=env["SECURITY_PASSWORD_SALT"], max_age=expiration
        )
        return email
    except Exception:
        return False


@auth.route("/signup", methods=["GET"])
def signup_get():
    return render_template("signup.html", captcha_sitekey=env['RECAPTCHA_PUBLIC_KEY'])


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.index"))


@auth.route("/reset-password", methods=["GET"])
def password_reset_get():
    return render_template("reset_password.html", captcha_sitekey=env['RECAPTCHA_PUBLIC_KEY'])


@auth.route("/reset-password", methods=["POST"])
@limiter.limit("5/minute")
def password_reset_post():
    email = request.form.get("email")
    user = User.query.filter_by(email=email).first()

    if not user:
        flash("Could not find that user in the database")
        return redirect(url_for("auth.password_reset_get"))

    if is_bot(request):
        flash("Captcha failed")
        return redirect(url_for("auth.signup_get"))

    token = str(uuid4())
    token_urlsafe = parse.quote_plus(token)

    reset = PasswordReset(for_user=user.id, token=token)
    db.session.add(reset)
    db.session.commit()

    # Use Gmail SMTP for password reset email
    sender_email = env.get('EMAIL_ADDRESS')
    sender_password = env.get('EMAIL_PASSWORD')
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = "Password Reset Request"
    
    body = f"""Hello {user.username}!
    
You've requested a password reset. If this wasn't you, please ignore this email.

Click on the following link to reset your password:
https://lovejoy-antique.onrender.com/reset-password/{token_urlsafe}

This link will expire in 30 minutes.
"""
    
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, email, text)
        server.quit()
        
        flash(f"We've sent you a password reset email at {email}")
        return redirect(url_for("auth.login_get"))
    except Exception as e:
        logger.error(f"Failed to send password reset email: {str(e)}")
        flash("Failed to send password reset email. Please try again.")
        return redirect(url_for("auth.password_reset_get"))


@auth.route('/reset-password/<token>', methods=["GET"])
@limiter.limit("5/minute")
def handle_password_reset(token):
    reset = PasswordReset.query.filter_by(token=token).first()

    if reset is None: 
        flash("Invalid Token")
        return redirect(url_for("auth.password_reset_get"))
            
    time_elapsed_since_request = datetime.utcnow() - reset.requested

    if time_elapsed_since_request > PASSWORD_RESET_TIMEOUT:
        flash("That token has expired")
        return redirect(url_for("auth.password_reset_get"))

    return render_template('change_password.html', token=token)


@auth.route('/reset-password/<token>', methods=["POST"])
@limiter.limit("5/minute")
def handle_password_reset_post(token):
    reset = PasswordReset.query.filter_by(token=token).first()
    new_password = request.form.get('password')         
    requested_by = User.query.filter_by(id=reset.for_user).first()

    if not password_meets_security_requirements(new_password):
        flash("Password does not meet our security requirements")
        return redirect(url_for('auth.handle_password_reset', token=token))         

    requested_by.password = generate_password_hash(new_password)
    reset.has_reset = True 
    db.session.commit()

    flash("Your password has been reset!")
    return redirect(url_for('auth.login_get'))


@auth.route("/verify-otp/<email>", methods=["GET"])
def verify_otp(email):
    return render_template("verify_otp.html", email=email)


@auth.route("/verify-otp/<email>", methods=["POST"])
@limiter.limit("5/minute")
def verify_otp_post(email):
    otp = request.form.get("otp")
    user = User.query.filter_by(email=email).first()
    
    if not user:
        flash("Invalid request")
        return redirect(url_for("auth.login_get"))
    
    # Check if OTP is expired (5 minutes)
    if datetime.utcnow() - user.otp_created_at > timedelta(minutes=5):
        flash("OTP has expired. Please login again.")
        return redirect(url_for("auth.login_get"))
    
    if user.otp == otp:
        user.otp = None
        user.otp_created_at = None
        db.session.commit()
        login_user(user)
        return redirect(url_for("main.profile"))
    else:
        flash("Invalid OTP")
        return redirect(url_for("auth.verify_otp", email=email))


@auth.route("/verify-signup-otp/<email>", methods=["GET"])
def verify_signup_otp(email):
    return render_template("verify_otp.html", email=email, signup=True)


@auth.route("/verify-signup-otp/<email>", methods=["POST"])
@limiter.limit("5/minute")
def verify_signup_otp_post(email):
    otp = request.form.get("otp")
    user = User.query.filter_by(email=email).first()
    
    if not user:
        flash("Invalid request")
        return redirect(url_for("auth.signup_get"))
    
    # Check if OTP is expired (5 minutes)
    if datetime.utcnow() - user.otp_created_at > timedelta(minutes=5):
        # Delete the unverified user
        db.session.delete(user)
        db.session.commit()
        flash("OTP has expired. Please sign up again.")
        return redirect(url_for("auth.signup_get"))
    
    if user.otp == otp:
        user.email_verified = True
        user.otp = None
        user.otp_created_at = None
        db.session.commit()
        login_user(user)
        return redirect(url_for("main.profile"))
    else:
        flash("Invalid OTP")
        return redirect(url_for("auth.verify_signup_otp", email=email))