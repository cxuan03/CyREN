"""
Entry point for CyREN.

    python run.py

Then open http://localhost:5000

With ENABLE_SCHEDULER=true the background pipeline (Elasticsearch polling ->
multi-agent analysis -> persistence) starts automatically alongside the web app.
"""
import os

from app import create_app
from config.settings import settings

app = create_app()

if __name__ == "__main__":
    debug = settings.FLASK_ENV == "development"
    # With the Flask debug reloader active, only start the scheduler in the
    # reloaded child process so it does not run twice.
    if settings.ENABLE_SCHEDULER and (not debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true"):
        from app.services.scheduler import start_scheduler
        start_scheduler(app)
    app.run(host="0.0.0.0", port=5000, debug=debug)
