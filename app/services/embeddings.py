"""
Gemini embeddings for the MITRE ATT&CK knowledge base (GraphRAG retrieval).

The InvestigationAgent embeds the query and the corpus in the *same* Gemini
embedding space, so ChromaDB vector search is meaningful. The heavy reasoning
LLM stays local (Ollama); only these small embedding calls use Gemini, and
every caller is expected to degrade gracefully to the static fallback map when
Gemini is unreachable, so an offline demo still runs.

    from app.services import embeddings as emb
    vec = emb.embed_query("SQL Injection ...")     # query-side vector
    vec = emb.embed_document("T1190 Exploit ...")  # corpus-side vector
"""
import logging

from config.settings import settings

log = logging.getLogger(__name__)

# A missing/broken google-generativeai package must be visible (carried into the
# raised error), not silently turn every retrieval into the static fallback with
# nothing in the logs to explain why.
try:
    import google.generativeai as genai
    _IMPORT_ERROR = None
except Exception as exc:                       # noqa: BLE001 - report any cause
    genai = None
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_configured = False


def available() -> bool:
    """True when Gemini embeddings can actually be requested."""
    return genai is not None and bool(settings.GEMINI_API_KEY)


def _configure() -> None:
    global _configured
    if not _configured:
        genai.configure(api_key=settings.GEMINI_API_KEY)
        _configured = True


def _embed(text: str, task_type: str) -> list:
    if genai is None:
        raise RuntimeError(f"google-generativeai unavailable ({_IMPORT_ERROR})")
    if not settings.GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY is not set in .env")
    _configure()
    res = genai.embed_content(
        model=settings.GEMINI_EMBED_MODEL, content=text, task_type=task_type)
    return res["embedding"]


def embed_document(text: str) -> list:
    """Embed a corpus document (used when building the knowledge base)."""
    return _embed(text, "retrieval_document")


def embed_query(text: str) -> list:
    """Embed a search query (used at retrieval time)."""
    return _embed(text, "retrieval_query")
