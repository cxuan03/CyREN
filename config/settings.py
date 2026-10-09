"""
Central configuration for CyREN.

All values are read from environment variables (loaded from .env) so that
secrets never live in the codebase. Import `settings` anywhere you need a
configured value:

    from config.settings import settings
    client = Groq(api_key=settings.GROQ_API_KEY)
"""
import io
import os

from dotenv import load_dotenv, dotenv_values

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_env() -> None:
    """Load configuration into the environment.

    Prefer an encrypted .env.enc (decrypted with the CYREN_SECRET_KEY env var)
    so secrets never sit in plaintext in the repo or the submission. Fall back
    to a plaintext .env for local development. A missing or wrong key never
    crashes startup -- it degrades to the plaintext .env.
    """
    enc = os.path.join(_ROOT, ".env.enc")
    key = os.getenv("CYREN_SECRET_KEY")
    if os.path.exists(enc) and key:
        try:
            from cryptography.fernet import Fernet
            plain = Fernet(key.encode()).decrypt(open(enc, "rb").read()).decode("utf-8")
            for k, v in dotenv_values(stream=io.StringIO(plain)).items():
                if v is not None:
                    os.environ.setdefault(k, v)   # never override a real OS env var
            return
        except Exception as exc:  # unreadable/absent key -> fall back, never crash
            print(f"[settings] .env.enc present but not decrypted ({exc}); using plaintext .env")
    load_dotenv(os.path.join(_ROOT, ".env"))


_load_env()


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

    # Origins allowed to make credentialed cross-origin requests. CyREN's UI is
    # same-origin, so this is a tight allow-list (localhost + the host-only IP),
    # not a wildcard. Override with a comma-separated CORS_ORIGINS in .env.
    CORS_ORIGINS = [
        o.strip() for o in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5000,http://127.0.0.1:5000,http://192.168.56.1:5000",
        ).split(",") if o.strip()
    ]

    # The Werkzeug interactive debugger is a remote-code-execution surface, so it
    # is OFF by default and must be opted into explicitly (local dev only, never
    # on a network-reachable instance). FLASK_ENV=development still enables the
    # auto-reloader without exposing the debugger.
    FLASK_DEBUG = os.getenv("FLASK_DEBUG", "false").strip().lower() in ("1", "true", "yes", "on")
    # Idle auto-logout: minutes of inactivity before a signed-in session expires.
    IDLE_TIMEOUT_MINUTES = int(os.getenv("IDLE_TIMEOUT_MINUTES", "30") or 30)

    # ---- Elasticsearch ----
    ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
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
    # 10.0.2.2 is the VirtualBox NAT gateway: SSH/traffic that traverses NAT
    # reaches the target with this source, so it shows up as a phantom attacker.
    SOURCE_IP_BLACKLIST = os.getenv(
        "SOURCE_IP_BLACKLIST",
        "127.0.0.0/8,::1,192.168.56.1,10.0.2.2",
    )

    # ---- Background pipeline scheduler ----
    ENABLE_SCHEDULER = _bool("ENABLE_SCHEDULER", False)
    POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "15") or 15)
    # New activity from the same (source_ip, rule) that arrives more than this many
    # hours after the existing event's last activity starts a NEW event (a new
    # attack "session"), instead of merging - so an event's first/last seen span
    # one session rather than weeks. Attack chains still correlate by source IP.
    SESSION_GAP_HOURS = _float("SESSION_GAP_HOURS", 6.0)

    # ---- Triage ----
    XGBOOST_MODEL_PATH = os.getenv("XGBOOST_MODEL_PATH", "data/models/triage_xgb.json")
    RULE_MAP_PATH = os.getenv("RULE_MAP_PATH", "data/models/rule_map.json")
    HIGH_RISK_THRESHOLD = _float("HIGH_RISK_THRESHOLD", 0.85)
    LOW_RISK_THRESHOLD = _float("LOW_RISK_THRESHOLD", 0.40)

    # ---- Investigation ----
    # LLM provider: "groq" (cloud, free tier) or "ollama" (local, unlimited, offline).
    # Ollama runs the model on this machine, so there is no cloud dependency and no
    # model-decommission churn; set LLM_PROVIDER=ollama once Ollama is installed and
    # the model pulled. OLLAMA_MODEL is an Ollama tag (e.g. llama3.1:8b).
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq").strip().lower()
    OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
    # Keep the model resident in VRAM between calls so there is no ~60s cold-start
    # reload each time it goes idle ("30m" = keep 30 min after last use; "-1" = forever).
    OLLAMA_KEEP_ALIVE = os.getenv("OLLAMA_KEEP_ALIVE", "30m")

    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
    # Model history on Groq: Llama 4 Scout was retired (404 model_not_found),
    # then llama-3.1-8b-instant was decommissioned (2026-08-16). The default is
    # now llama-3.3-70b-versatile, which emits response_format=json_object
    # directly within GROQ_MAX_TOKENS (the InvestigationAgent relies on this).
    # NOTE: Groq's suggested replacement openai/gpt-oss-20b is a *reasoning* model
    # that consumes the token budget on internal reasoning and fails to complete
    # the JSON at 500 tokens (it needs ~3000), so it does not suit this tight-token
    # design without also raising GROQ_MAX_TOKENS. Run scripts/check_llm.py to list
    # what a key can currently access.
    GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    # Cap the analysis length to save output tokens (they count toward quota).
    GROQ_MAX_TOKENS = int(os.getenv("GROQ_MAX_TOKENS", "500") or 500)
    CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "data/chroma")
    CHROMA_COLLECTION = os.getenv("CHROMA_COLLECTION", "mitre_attack")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    GEMINI_EMBED_MODEL = os.getenv("GEMINI_EMBED_MODEL", "models/gemini-embedding-001")

    # ---- Response ----
    ENABLE_IPTABLES = _bool("ENABLE_IPTABLES", False)
    IPTABLES_CHAIN = os.getenv("IPTABLES_CHAIN", "CYREN_BLOCK")
    # Static token for the read-only /api/blocklist feed consumed by the
    # enforcement agent on the target host. Empty = feed disabled.
    BLOCKLIST_TOKEN = os.getenv("BLOCKLIST_TOKEN", "")
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
