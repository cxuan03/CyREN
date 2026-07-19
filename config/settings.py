"""
Central configuration for CyREN.

All values are read from environment variables (loaded from .env) so that
secrets never live in the codebase. Import `settings` anywhere you need a
configured value:

    from config.settings import settings
    client = Groq(api_key=settings.GROQ_API_KEY)
"""
import os
from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


class Settings:
    # ---- Flask ----
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///data/cyren.db")

    # ---- Elasticsearch ----
    ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://192.168.56.10:9200")
    ELASTICSEARCH_USER = os.getenv("ELASTICSEARCH_USER", "elastic")
    ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "")
    ELASTIC_ALERT_INDEX = os.getenv("ELASTIC_ALERT_INDEX", ".alerts-security.alerts-default")
    FETCH_WINDOW_HOURS = int(os.getenv("FETCH_WINDOW_HOURS", "24") or 24)

    # ---- Background pipeline scheduler ----
    ENABLE_SCHEDULER = _bool("ENABLE_SCHEDULER", False)
    POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "60") or 60)

    # ---- Triage ----
    XGBOOST_MODEL_PATH = os.getenv("XGBOOST_MODEL_PATH", "data/models/triage_xgb.json")
    RULE_MAP_PATH = os.getenv("RULE_MAP_PATH", "data/models/rule_map.json")
    HIGH_RISK_THRESHOLD = _float("HIGH_RISK_THRESHOLD", 0.85)
    LOW_RISK_THRESHOLD = _float("LOW_RISK_THRESHOLD", 0.40)

    # ---- Investigation ----
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL = os.getenv("GROQ_MODEL", "meta-llama/llama-4-scout-17b-16e-instruct")
    CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "data/chroma")
    CHROMA_COLLECTION = os.getenv("CHROMA_COLLECTION", "mitre_attack")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    GEMINI_EMBED_MODEL = os.getenv("GEMINI_EMBED_MODEL", "models/text-embedding-004")

    # ---- Response ----
    ENABLE_IPTABLES = _bool("ENABLE_IPTABLES", False)
    IPTABLES_CHAIN = os.getenv("IPTABLES_CHAIN", "CYREN_BLOCK")
    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or 587)
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "")

    # ---- Reports ----
    REPORT_OUTPUT_DIR = os.getenv("REPORT_OUTPUT_DIR", "data/reports")


settings = Settings()
