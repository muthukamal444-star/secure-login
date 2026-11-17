import os
import re
import io
import base64
import secrets
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
import pyotp
import qrcode
from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///secure_auth.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    two_factor_enabled = db.Column(db.Boolean, default=False, nullable=False)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


with app.app_context():
    db.create_all()


EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,30}$")


def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def validate_registration(username: str, email: str, password: str, confirm_password: str):
    errors = []
    if not USERNAME_REGEX.match(username):
        errors.append("Username must be 3-30 characters (letters, numbers, underscores only).")
    if not EMAIL_REGEX.match(email):
        errors.append("Please enter a valid email address.")
    if password != confirm_password:
        errors.append("Passwords do not match.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*(),.?":{}|<>_\-]", password):
        errors.append("Password must contain at least one special character.")
    return errors


def generate_qr_base64(uri: str) -> str:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        errors = validate_registration(username, email, password, confirm_password)

        if User.query.filter_by(username=username).first():
            errors.append("Username is already taken.")
        if User.query.filter_by(email=email).first():
            errors.append("Email is already registered.")

        if errors:
            for err in errors:
                flash(err, "danger")
            return render_template("register.html", username=username, email=email)

        new_user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        if not identifier or not password:
            flash("Please provide both username/email and password.", "danger")
            return render_template("login.html")

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if user and user.locked_until and user.locked_until > datetime.utcnow():
            remaining = int((user.locked_until - datetime.utcnow()).total_seconds() // 60) + 1
            flash(f"Account temporarily locked due to failed attempts. Try again in {remaining} min.", "danger")
            return render_template("login.html")

        if not user or not verify_password(password, user.password_hash):
            if user:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=5)
                    user.failed_attempts = 0
                db.session.commit()
            flash("Invalid credentials.", "danger")
            return render_template("login.html")

        user.failed_attempts = 0
        user.locked_until = None
        db.session.commit()

        if user.two_factor_enabled and user.totp_secret:
            session.clear()
            session["pre_2fa_user_id"] = user.id
            return redirect(url_for("verify_2fa"))

        session.clear()
        session.permanent = True
        session["user_id"] = user.id
        session["username"] = user.username
        flash("Logged in successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    pre_user_id = session.get("pre_2fa_user_id")
    if not pre_user_id:
        return redirect(url_for("login"))

    user = db.session.get(User, pre_user_id)
    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_code = request.form.get("otp_code", "").strip()
        if not otp_code.isdigit() or len(otp_code) != 6:
            flash("Enter a valid 6-digit authenticator code.", "danger")
            return render_template("verify_2fa.html")

        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(otp_code, valid_window=1):
            session.clear()
            session.permanent = True
            session["user_id"] = user.id
            session["username"] = user.username
            flash("Two-Factor Authentication verified!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid or expired 2FA code.", "danger")

    return render_template("verify_2fa.html")


@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = db.session.get(User, session["user_id"])

    if request.method == "POST":
        action = request.form.get("action")
        if action == "disable":
            user.two_factor_enabled = False
            user.totp_secret = None
            db.session.commit()
            flash("Two-Factor Authentication has been disabled.", "info")
            return redirect(url_for("dashboard"))

        otp_code = request.form.get("otp_code", "").strip()
        temp_secret = session.get("temp_totp_secret")
        if not temp_secret:
            flash("2FA setup session expired. Please try again.", "danger")
            return redirect(url_for("setup_2fa"))

        totp = pyotp.TOTP(temp_secret)
        if totp.verify(otp_code, valid_window=1):
            user.totp_secret = temp_secret
            user.two_factor_enabled = True
            db.session.commit()
            session.pop("temp_totp_secret", None)
            flash("Two-Factor Authentication enabled successfully!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid verification code. Please scan the QR code and try again.", "danger")

    temp_secret = session.get("temp_totp_secret") or pyotp.random_base32()
    session["temp_totp_secret"] = temp_secret
    totp_uri = pyotp.totp.TOTP(temp_secret).provisioning_uri(
        name=user.email, issuer_name="SecureAuthApp"
    )
    qr_b64 = generate_qr_base64(totp_uri)

    return render_template(
        "setup_2fa.html",
        user=user,
        secret=temp_secret,
        qr_b64=qr_b64,
    )


@app.route("/dashboard")
@login_required
def dashboard():
    user = db.session.get(User, session["user_id"])
    return render_template("dashboard.html", user=user)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
