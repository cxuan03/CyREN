# -*- coding: utf-8 -*-
"""Set (or clear) the ingest watermark — the time CyREN starts ingesting logs
from. The poller only turns logs NEWER than this into events.

Use it when you attacked BEFORE resetting (so the watermark landed after your
attack and the poller skipped it): point the watermark back to just before the
attack and the next poll picks it up.

    venv\\Scripts\\python.exe scripts\\set_ingest_since.py 2026-08-22T07:50
    venv\\Scripts\\python.exe scripts\\set_ingest_since.py --now      # from now on
    venv\\Scripts\\python.exe scripts\\set_ingest_since.py --clear    # no watermark (lookback window)
"""
import sys
from datetime import datetime

sys.path.insert(0, ".")
from app import create_app                     # noqa: E402
from app.models.db import db, Setting          # noqa: E402


def main():
    args = [a for a in sys.argv[1:]]
    if not args:
        print(__doc__); return
    app = create_app()
    with app.app_context():
        cur = Setting.get("ingest_since")
        if "--clear" in args:
            Setting.set("ingest_since", None)
            db.session.commit()
            print(f"ingest watermark CLEARED (was {cur}). The poller now ingests "
                  "the whole lookback window; old logs may be re-processed.")
            return
        if "--now" in args:
            val = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        else:
            raw = args[0].strip().replace("Z", "").replace(" ", "T")[:19]
            try:
                val = datetime.fromisoformat(raw).strftime("%Y-%m-%dT%H:%M:%S")
            except ValueError:
                print(f"Bad time '{args[0]}'. Use ISO, e.g. 2026-08-22T07:50 (UTC)."); return
        Setting.set("ingest_since", val)
        db.session.commit()
        print(f"ingest watermark set to {val} UTC (was {cur}).")
        print("The next poll (a few seconds) will ingest logs from that time onward.")


if __name__ == "__main__":
    main()
