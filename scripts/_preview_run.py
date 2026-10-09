"""Throwaway preview runner for screenshots: starts the app on port 5050 with no
reloader and no background scheduler (the DB already has events to view)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False, use_reloader=False)
