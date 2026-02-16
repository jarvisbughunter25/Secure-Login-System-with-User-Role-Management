import os
import re
from datetime import datetime, timedelta, timezone
from functools import wraps
from secrets import randbelow

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash


db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

EMAIL_REGEX = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{10,128}$"
)
LOCKOUT_MINUTES = 15
MAX_FAILED_ATTEMPTS = 5
ALLOWED_ROLES = {"Admin", "User"}


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="User")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)

    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)

    @property
    def is_locked(self) -> bool:
        if not self.locked_until:
            return False
        lock_time = self.locked_until
        if lock_time.tzinfo is None:
            lock_time = lock_time.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) < lock_time


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)

    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-change-me"),
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///secure_login.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",
        REMEMBER_COOKIE_HTTPONLY=True,
    )

    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    login_manager.login_view = "login"

    @app.before_request
    def enforce_security_headers():
        if request.endpoint == "static":
            return None

    @app.after_request
    def set_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'"
        return response

    def validate_registration_form(username: str, email: str, password: str, role: str):
        errors = []
        if not username.strip() or len(username.strip()) < 3:
            errors.append("Username must be at least 3 characters.")
        if not EMAIL_REGEX.match(email):
            errors.append("Invalid email format.")
        if not PASSWORD_REGEX.match(password):
            errors.append(
                "Password must be 10+ chars and include uppercase, lowercase, number, and symbol."
            )
        if role not in ALLOWED_ROLES:
            errors.append("Invalid role selected.")
        return errors

    def refresh_captcha() -> tuple[str, int]:
        a = randbelow(9) + 1
        b = randbelow(9) + 1
        session["captcha_answer"] = a + b
        return f"What is {a} + {b}?", a + b

    def verify_captcha(answer: str) -> bool:
        try:
            return int(answer) == int(session.get("captcha_answer", -1))
        except ValueError:
            return False

    def role_required(*roles):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if current_user.role not in roles:
                    flash("Unauthorized access.", "danger")
                    return redirect(url_for("dashboard"))
                return func(*args, **kwargs)

            return wrapper

        return decorator

    @app.route("/")
    def home():
        return redirect(url_for("dashboard" if current_user.is_authenticated else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            role = request.form.get("role", "User")
            captcha = request.form.get("captcha", "")

            errors = validate_registration_form(username, email, password, role)
            if not verify_captcha(captcha):
                errors.append("CAPTCHA verification failed.")

            if User.query.filter(func.lower(User.email) == email).first():
                errors.append("Email already exists.")

            if errors:
                for error in errors:
                    flash(error, "danger")
                question, _ = refresh_captcha()
                return render_template("register.html", captcha_question=question), 400

            user = User(username=username, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

        question, _ = refresh_captcha()
        return render_template("register.html", captcha_question=question)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            captcha = request.form.get("captcha", "")

            if not EMAIL_REGEX.match(email):
                flash("Invalid email format.", "danger")
                question, _ = refresh_captcha()
                return render_template("login.html", captcha_question=question), 400

            user = User.query.filter(func.lower(User.email) == email).first()

            if not verify_captcha(captcha):
                flash("CAPTCHA verification failed.", "danger")
                question, _ = refresh_captcha()
                return render_template("login.html", captcha_question=question), 400

            if not user:
                flash("Invalid email or password.", "danger")
                question, _ = refresh_captcha()
                return render_template("login.html", captcha_question=question), 401

            if user.is_locked:
                flash("Account is temporarily locked due to failed attempts.", "danger")
                question, _ = refresh_captcha()
                return render_template("login.html", captcha_question=question), 423

            if not user.check_password(password):
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
                    user.failed_login_attempts = 0
                    flash("Account locked for 15 minutes after repeated failed logins.", "danger")
                else:
                    remaining = MAX_FAILED_ATTEMPTS - user.failed_login_attempts
                    flash(f"Invalid email or password. Attempts left before lockout: {remaining}.", "danger")
                db.session.commit()
                question, _ = refresh_captcha()
                return render_template("login.html", captcha_question=question), 401

            user.failed_login_attempts = 0
            user.locked_until = None
            db.session.commit()

            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))

        question, _ = refresh_captcha()
        return render_template("login.html", captcha_question=question)

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/admin")
    @login_required
    @role_required("Admin")
    def admin_dashboard():
        users = User.query.order_by(User.created_at.desc()).all()
        return render_template("admin.html", users=users)

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        logout_user()
        flash("Logged out successfully.", "success")
        return redirect(url_for("login"))

    with app.app_context():
        db.create_all()

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
