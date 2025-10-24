# phishdetect/config.py

# Paths and model settings
DATA_DIR = "data"
MODEL_PATH = "models/phish_model.pkl"
DEFAULT_THRESHOLD = 0.50

# Flask secret key
SECRET_KEY = "replace-with-a-long-random-secret"

# MongoDB is configured directly in app.py, no SQLAlchemy needed.
SQLALCHEMY_DATABASE_URI = "sqlite:///phishdetect.db"   # unused but harmless
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Email (SMTP) settings for Gmail
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "jeetdas1308op@gmail.com"
SMTP_PASS = "fngiaaegfinsiomk"   # your Gmail App Password
EMAIL_FROM = f"PhishDetect <{SMTP_USER}>"

# Optional toggle to skip sending emails in dev mode
SEND_EMAIL = True
