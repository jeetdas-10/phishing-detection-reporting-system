# phishdetect/app.py
import io
import os
import smtplib
from email.message import EmailMessage
from urllib.parse import urlparse
from datetime import datetime

import pandas as pd
from flask import (
    Flask, request, jsonify, render_template,
    send_file, redirect, url_for, flash, abort, current_app
)
from flask_pymongo import PyMongo
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from bson import ObjectId
from email_validator import validate_email, EmailNotValidError

# project imports (make sure config.py defines these names)
from phishdetect.config import (
    MODEL_PATH, DEFAULT_THRESHOLD,
    SECRET_KEY, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, EMAIL_FROM, SEND_EMAIL
)
from phishdetect.model_utils import load_model, get_probabilities
from phishdetect.domain_utils import registered_domain, load_allowlist

# -------------------------
# Flask + Mongo setup
# -------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = SECRET_KEY or "dev-secret-change-me"
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
app.config["MONGO_URI"] = os.getenv("MONGO_URI", "mongodb://localhost:27017/phishdetect")
app.config["SEND_EMAIL"] = bool(SEND_EMAIL)

mongo = PyMongo(app)
users_coll = mongo.db.users
reports_coll = mongo.db.reports

login_manager = LoginManager(app)
login_manager.login_view = "login"

# -------------------------
# Minimal User wrapper for Flask-Login
# -------------------------
class User(UserMixin):
    def __init__(self, doc):
        self._doc = doc
        self.id = str(doc["_id"])
        self.email = doc.get("email")
        self.is_admin = doc.get("is_admin", False)

    def check_password(self, password):
        return check_password_hash(self._doc["password_hash"], password)


@login_manager.user_loader
def load_user(user_id):
    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    doc = users_coll.find_one({"_id": oid})
    return User(doc) if doc else None

# -------------------------
# Model load + constants
# -------------------------
try:
    model = load_model(MODEL_PATH)
    app.logger.info("Model loaded from %s", MODEL_PATH)
except Exception as e:
    model = None
    app.logger.exception("Failed to load model from %s: %s", MODEL_PATH, e)

ALLOWED_EXTENSIONS = {"csv"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# -------------------------
# Routes: Landing / Auth
# -------------------------
@app.route("/", methods=["GET"])
def landing():
    return render_template("landing.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError:
            flash("Invalid email address.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("register"))

        if users_coll.find_one({"email": email}):
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for("login"))

        users_coll.insert_one({
            "email": email,
            "password_hash": generate_password_hash(password),
            "is_admin": False,
            "created_at": datetime.utcnow()
        })
        flash("Registration successful — please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not email or not password:
            flash("Email and password required", "danger")
            return redirect(url_for("login"))

        doc = users_coll.find_one({"email": email})
        if not doc or not check_password_hash(doc["password_hash"], password):
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))

        user = User(doc)
        login_user(user)
        flash("Logged in", "success")
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("login"))

# -------------------------
# Protected Dashboard (prediction UI)
# -------------------------
@app.route("/index")
@login_required
def index():
    return render_template("index.html")


# -------------------------
# Prediction API (public)
# -------------------------
@app.route("/api/predict", methods=["POST"])
def api_predict():
    if model is None:
        return jsonify({"error": "Model not loaded"}), 500
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400

    urls = body.get("urls", [])
    if not isinstance(urls, list) or not urls:
        return jsonify({"error": "Provide a non-empty 'urls' list"}), 400

    threshold = float(body.get("threshold", DEFAULT_THRESHOLD))
    probs = get_probabilities(model, urls)
    preds = (probs >= threshold).astype(int)
    return jsonify({"pred": preds.tolist(), "prob": probs.tolist()})


# -------------------------
# Reports
# -------------------------
@app.route("/report", methods=["POST"])
@login_required
def report():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()
    comment = data.get("comment", "").strip() if data.get("comment") else None

    if not url:
        return jsonify({"error": "url required"}), 400

    try:
        domain = registered_domain(url)
    except Exception:
        domain = urlparse(url).netloc or url

    report_doc = {
        "user_id": ObjectId(current_user.id),
        "user_email": current_user.email,
        "url": url,
        "domain": domain,
        "comment": comment,
        "created_at": datetime.utcnow(),
        "email_sent": False
    }
    res = reports_coll.insert_one(report_doc)

    sent = False
    try:
        send_report_email(current_user.email, report_doc)
        reports_coll.update_one({"_id": res.inserted_id}, {"$set": {"email_sent": True}})
        sent = True
    except Exception as e:
        app.logger.exception("Failed to send report email: %s", e)

    return jsonify({"ok": True, "report_id": str(res.inserted_id), "email_sent": sent})


@app.route("/reports")
@login_required
def view_reports():
    if not getattr(current_user, "is_admin", False):
        abort(403)
    docs = list(reports_coll.find().sort("created_at", -1))
    return render_template("reports.html", reports=docs)


# -------------------------
# Test email route (protected)
# -------------------------
@app.route("/test-email")
@login_required
def test_email():
    if not current_user.email:
        flash("No email available for current user", "danger")
        return redirect(url_for("index"))
    doc = {
        "url": "https://example.com/test",
        "domain": "example.com",
        "comment": "Test email from /test-email",
        "created_at": datetime.utcnow()
    }
    try:
        send_report_email(current_user.email, doc)
        flash("Test email attempted (check your inbox)", "info")
    except Exception as e:
        app.logger.exception("Test email failed: %s", e)
        flash("Test email failed (see server logs).", "danger")
    return redirect(url_for("index"))


# -------------------------
# Email helper
# -------------------------
def send_report_email(to_email, report_doc):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        current_app.logger.warning("SMTP credentials not configured; skipping email.")
        return

    if not current_app.config.get("SEND_EMAIL", True):
        current_app.logger.info("SEND_EMAIL=False; skipping actual send.")
        return

    msg = EmailMessage()
    msg["Subject"] = "PhishDetect — report received"
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email
    msg.set_content(f"""Hello,

Thanks — we received your report.

URL: {report_doc.get('url')}
Domain: {report_doc.get('domain')}
Comment: {report_doc.get('comment') or '(none)'}
Time: {report_doc.get('created_at')}

— PhishDetect
""")

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
            current_app.logger.info("Email sent to %s", to_email)
    except Exception as e:
        current_app.logger.exception("Email sending failed: %s", e)


# -------------------------
# Entry point
# -------------------------
if __name__ == "__main__":
    print("🚀 Starting PhishDetect Flask server...")
    app.run(host="127.0.0.1", port=5000, debug=True)
