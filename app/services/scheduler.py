"""
Background scheduler: the automation loop that replaces the prototype's
standalone backend.py.

Every POLL_INTERVAL_SECONDS it:
    1. pulls aggregated events from Elasticsearch (siem_service),
    2. skips events whose (source_ip, rule) pair has no new raw logs since
       the last run (the DB is the dedup memory, replacing the prototype's
       analyzed_ids list),
    3. runs each new/updated event through the multi-agent pipeline,
    4. persists the result via event_service.

Enable with ENABLE_SCHEDULER=true. Runs as a daemon thread inside the Flask
process, so `python run.py` starts the whole system.
"""
import threading
import time
from datetime import datetime

from config.settings import settings


def _is_new_activity(existing, event) -> bool:
    """Should this aggregate be (re)analysed?

    Reprocess when more raw logs folded in *or* when the aggregate now
    extends past what we last saw. Comparing log_count alone is not enough:
    the fetch window slides, so old alerts age out as new ones arrive and the
    count can stay flat or even shrink while genuinely new activity happened.
    """
    if existing is None:
        return True
    if (event.get("log_count") or 0) > (existing.log_count or 0):
        return True
    last_seen = (event.get("last_seen") or "").replace("T", " ")[:19]
    known = existing.last_seen.isoformat().replace("T", " ")[:19] if existing.last_seen else ""
    return bool(last_seen and last_seen > known)


def _process_once(app) -> int:
    """One polling cycle; returns how many events were (re)analysed."""
    from app.agents.pipeline import run_pipeline
    from app.models.db import Event
    from app.services.event_service import persist_pipeline_result
    from app.services.siem_service import siem_service

    processed = 0
    with app.app_context():
        events = siem_service.fetch_aggregated_events()
        skipped = 0
        for event in events:
            existing = (Event.query
                        .filter_by(source_ip=event.get("source_ip"), rule=event.get("rule"))
                        .filter(Event.status != "dismissed")
                        .order_by(Event.id.desc())
                        .first())
            if not _is_new_activity(existing, event):
                skipped += 1
                continue

            print(f"[scheduler] analysing {event.get('rule')} from "
                  f"{event.get('source_ip')} ({event.get('log_count')} logs)")
            state = run_pipeline(event)
            persist_pipeline_result(state)
            processed += 1
        if skipped:
            print(f"[scheduler] {skipped} aggregate(s) unchanged, skipped")
    return processed


def _loop(app):
    print(f"[scheduler] started, polling every {settings.POLL_INTERVAL_SECONDS}s")
    while True:
        try:
            n = _process_once(app)
            if n:
                print(f"[scheduler] {datetime.now().strftime('%H:%M:%S')} "
                      f"processed {n} event(s)")
        except Exception as exc:
            print(f"[scheduler] cycle failed: {exc}")
        time.sleep(settings.POLL_INTERVAL_SECONDS)


def start_scheduler(app):
    """Start the polling loop in a daemon thread (call once per process)."""
    thread = threading.Thread(target=_loop, args=(app,), daemon=True,
                              name="cyren-scheduler")
    thread.start()
    return thread
