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

    # Where events come from:
    #   "filebeat" (default) - CyREN reads the detection-rule *definitions*
    #       from Kibana, then matches those queries against the raw filebeat
    #       logs itself. This does NOT depend on the Kibana detection engine
    #       running, so traffic (attack AND benign) becomes events reliably.
    #   "alerts" - read the Kibana security alert index (only works while the
    #       Kibana detection rules are enabled and firing).
    #   "both" - union of the two (may double-count a log that is both).
    INGEST_MODE = os.getenv("INGEST_MODE", "filebeat")
    FILEBEAT_INDEX = os.getenv("FILEBEAT_INDEX", "filebeat*")
    # Kibana index holding the detection-rule definitions (query, index, ...).
    KIBANA_RULES_INDEX = os.getenv("KIBANA_RULES_INDEX", ".kibana_alerting_cases*")
    # Max raw docs pulled per rule per poll in filebeat mode (caps log_count).
    FILEBEAT_MAX_DOCS = int(os.getenv("FILEBEAT_MAX_DOCS", "3000") or 3000)

    # How far back each poll looks. Lab alerts are generated in bursts and
    # then sit idle for days, so a 24h window silently goes empty between
    # sessions; a week keeps the whole experiment in view. Use
    # scripts/backfill_events.py for anything older.
    FETCH_WINDOW_HOURS = int(os.getenv("FETCH_WINDOW_HOURS", "168") or 168)

    # Source IPs whose alerts are noise, not attacks: loopback and the
    # VirtualBox host-only gateway (the host machine itself). Alerts from
    # these are dropped before an event is created. Comma-separated; each
    # entry may be a single IP or a CIDR range (e.g. "127.0.0.0/8").
    SOURCE_IP_BLACKLIST = os.getenv(
        "SOURCE_IP_BLACKLIST",
        "127.0.0.0/8,::1,192.168.56.1",
    )

    # ---- Background pipeline scheduler ----
    ENABLE_SCHEDULER = _bool("ENABLE_SCHEDULER", False)
    POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "15") or 15)

    # ---- Triage ----
    XGBOOST_MODEL_PATH = os.getenv("XGBOOST_MODEL_PATH", "data/models/triage_xgb.json")
    RULE_MAP_PATH = os.getenv("RULE_MAP_PATH", "data/models/rule_map.json")
    HIGH_RISK_THRESHOLD = _float("HIGH_RISK_THRESHOLD", 0.85)
    LOW_RISK_THRESHOLD = _float("LOW_RISK_THRESHOLD", 0.40)

    # ---- Investigation ----
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
    # Llama 4 Scout was retired from Groq (404 model_not_found). 8b-instant is
    # the default: it has a much larger free-tier token budget and costs fewer
    # tokens per call than 70b, which matters for the daily rate limit. Switch
    # to llama-3.3-70b-versatile in .env for higher quality when quota allows.
    # Run scripts/check_llm.py to list what a key can access.
    GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
    # Cap the analysis length to save output tokens (they count toward quota).
    GROQ_MAX_TOKENS = int(os.getenv("GROQ_MAX_TOKENS", "500") or 500)
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
    # Base URL of the CyREN web app, used to build the "open in CyREN" link in
    # the alert email so an analyst can jump straight to the incident.
    APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:5000")

    # ---- Reports ----
    REPORT_OUTPUT_DIR = os.getenv("REPORT_OUTPUT_DIR", "data/reports")


settings = Settings()
