import os


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret-key-change")
    DB_PATH = os.getenv("LOAN_DB_PATH", os.path.join(os.getcwd(), "loan_suite.db"))
    CLOUD_DB_URL = os.getenv("CLOUD_DB_URL", "").strip()
    CLOUD_DB_SSLMODE = os.getenv("CLOUD_DB_SSLMODE", "require").strip()
    MODEL_DIR = os.getenv("LOAN_MODEL_DIR", os.path.join(os.getcwd(), "model_store"))
    DATA_KEY = os.getenv("DATA_KEY", "dev-data-key-change")
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "jpcharlie2")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "guidewire@2026")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    PERMANENT_SESSION_LIFETIME_MIN = 60
    RATE_LIMIT_WINDOW_SEC = 60
    RATE_LIMIT_MAX = 50
    LOGIN_LOCK_THRESHOLD = 5
    LOGIN_LOCK_MINUTES = 15
    CHATBOT_MAX_INPUT = 500
    CHATBOT_ENABLE_OPENAI = False
    CHATBOT_ENABLE_GEMINI = os.getenv("CHATBOT_ENABLE_GEMINI", "1").strip() in {"1", "true", "TRUE", "yes", "YES"}
