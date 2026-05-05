import os


def _default_db_path() -> str:
    configured = os.getenv("LOAN_DB_PATH")
    if configured:
        return configured

    cwd = os.getcwd()
    legacy_path = os.path.join(cwd, "loan_suite.db")
    if os.path.exists(legacy_path):
        return legacy_path
    return os.path.join(cwd, "loanshield.db")


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret-key-change")
    DB_PATH = _default_db_path()
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
