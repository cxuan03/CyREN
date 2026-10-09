"""
Entry point for CyREN.

    python run.py

Then open http://localhost:5000

With ENABLE_SCHEDULER=true the background pipeline (Elasticsearch polling ->
multi-agent analysis -> persistence) starts automatically alongside the web app.
"""
import os
import threading

from app import create_app
from config.settings import settings

app = create_app()


def _warm_llm():
    """When the LLM runs locally on Ollama, load the model into VRAM in the
    background at startup. Ollama loads a model only on its first call (~60s for
    an 8B model), so without this the first real analysis or chain prediction
    would pay that cold-start. Doing it here, off the request path, means the
    model is already warm by the time an analyst (or a viva examiner) uses it.
    Non-blocking and best-effort: any failure is logged, never fatal."""
    if settings.LLM_PROVIDER != "ollama":
        return

    def _go():
        try:
            from app.agents.investigation import _investigation
            _investigation._chat_json('Reply with JSON {"ok":true}', 0.0, 16)
            print(f"[warmup] Ollama model '{settings.OLLAMA_MODEL}' preloaded into VRAM")
        except Exception as exc:                     # noqa: BLE001
            print(f"[warmup] Ollama warm-up skipped: {type(exc).__name__}: {exc}")

    threading.Thread(target=_go, daemon=True).start()


if __name__ == "__main__":
    # The app listens on 0.0.0.0 (the target host pulls the blocklist over the
    # host-only network), so the Werkzeug interactive debugger — a remote code
    # execution surface — must NOT be exposed. Debug is therefore OFF unless
    # FLASK_DEBUG is explicitly set (local dev only). The auto-reloader still
    # runs in development for convenience, without the debugger.
    debug = settings.FLASK_DEBUG
    use_reloader = settings.FLASK_ENV == "development"
    # With the reloader active, start the scheduler only in the reloaded child
    # process so it does not run twice.
    if settings.ENABLE_SCHEDULER and (not use_reloader or os.environ.get("WERKZEUG_RUN_MAIN") == "true"):
        from app.services.scheduler import start_scheduler
        start_scheduler(app)
        _warm_llm()   # preload the local Ollama model so the first call isn't cold
    app.run(host="0.0.0.0", port=5000, debug=debug, use_reloader=use_reloader)
