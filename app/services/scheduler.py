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
    from app.services.event_service import (persist_pipeline_result,
                                            suppressed_event, fold_into_suppressed)
    from app.services.siem_service import siem_service

    processed = 0
    with app.app_context():
        _notify_expired_suppressions(app)
        events = siem_service.fetch_aggregated_events()
        skipped = 0
        for event in events:
            # alert suppression: while a dismissed event for this (source_ip,
            # rule) is still within its keep period, fold repeats into it and
            # skip the pipeline (no new event, no block, no email)
            supp = suppressed_event(event.get("source_ip"), event.get("rule"))
            if supp is not None:
                if _is_new_activity(supp, event):
                    fold_into_suppressed(supp, event)
                else:
                    skipped += 1
                continue

            # the newest event for this (source_ip, rule) INCLUDING one marked as
            # a false positive: the fetch window re-aggregates the same old logs
            # every cycle, so a dismissed event must still count as "already
            # seen", otherwise marking it a false positive makes the next cycle
            # re-create it from the same logs (and auto-block again). Genuinely
            # new activity after the mark still passes, and persist_pipeline_result
            # then opens a fresh event rather than overwriting the dismissed one.
            existing = (Event.query
                        .filter_by(source_ip=event.get("source_ip"), rule=event.get("rule"))
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


def _notify_expired_suppressions(app):
    """When a suppression keep period passes, notify the analysts once so they
    can extend or reactivate. The event is never deleted; once suppressed_until
    is in the past it simply stops suppressing and repeats raise events again."""
    from app.models.db import db, Event, User, Notification
    now = datetime.utcnow()
    due = (Event.query
           .filter(Event.suppressed_until.isnot(None),
                   Event.suppressed_until <= now,
                   Event.suppress_notified.isnot(True))
           .all())
    if not due:
        return
    recipients = [u.id for u in User.query.filter_by(is_active=True).all()
                  if (u.permissions or {}).get("approve_events")]
    for e in due:
        e.suppress_notified = True
        text = ("Suppression expired for #%d %s from %s (%d repeats while suppressed). "
                "Extend or reactivate?" % (e.id, e.attack_type or "event",
                                           e.source_ip or "?", e.suppress_hits or 0))
        for uid in recipients:
            db.session.add(Notification(user_id=uid, kind="suppress_expired",
                                        ref_id=e.id, text=text[:300]))
    db.session.commit()


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
        # auto-retrain: fire a retrain if the user-configured interval has elapsed
        try:
            from app.api.routes import maybe_auto_retrain
            with app.app_context():
                maybe_auto_retrain()
        except Exception as exc:
            print(f"[scheduler] auto-retrain check failed: {exc}")
        # ticket auto-raise: open a case for any new chain / actionable source
        try:
            from app.services.ticket_service import auto_raise
            with app.app_context():
                n2 = auto_raise()
                if n2:
                    print(f"[scheduler] auto-raised {n2} ticket(s)")
        except Exception as exc:
            print(f"[scheduler] ticket auto-raise failed: {exc}")
        time.sleep(settings.POLL_INTERVAL_SECONDS)


def start_scheduler(app):
    """Start the polling loop in a daemon thread (call once per process)."""
    thread = threading.Thread(target=_loop, args=(app,), daemon=True,
                              name="cyren-scheduler")
    thread.start()
    return thread
