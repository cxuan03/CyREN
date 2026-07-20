"""
Pull historical alerts from Elasticsearch and run them through the pipeline.

The scheduler only looks back FETCH_WINDOW_HOURS. Use this to ingest older
alerts (e.g. after an attack session that predates the window, or to rebuild
a training set):

    venv/Scripts/python.exe scripts/backfill_events.py --hours 720
    venv/Scripts/python.exe scripts/backfill_events.py --hours 720 --dry-run
    venv/Scripts/python.exe scripts/backfill_events.py --hours 720 --force
"""
import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(message)s")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=720,
                    help="how far back to look (default 720 = 30 days)")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be ingested without running the pipeline")
    ap.add_argument("--force", action="store_true",
                    help="re-analyse aggregates even if they look unchanged")
    args = ap.parse_args()

    from app import create_app
    from app.agents.pipeline import run_pipeline
    from app.models.db import Event
    from app.services.event_service import persist_pipeline_result
    from app.services.scheduler import _is_new_activity
    from app.services.siem_service import siem_service

    app = create_app()
    with app.app_context():
        if siem_service.es is None:
            print("No Elasticsearch connection; check ELASTICSEARCH_* in .env.")
            return 1

        events = siem_service.fetch_aggregated_events(hours=args.hours)
        if not events:
            print(f"\nNo alerts found in the last {args.hours}h. Nothing to ingest.")
            return 0

        print(f"\n{len(events)} aggregate(s) found in the last {args.hours}h:\n")
        processed = 0
        for event in events:
            existing = (Event.query
                        .filter_by(source_ip=event.get("source_ip"), rule=event.get("rule"))
                        .filter(Event.status != "dismissed")
                        .order_by(Event.id.desc())
                        .first())
            new = args.force or _is_new_activity(existing, event)
            mark = "NEW " if existing is None else ("UPDATE" if new else "skip  ")
            print(f"  [{mark}] {event['rule']:28s} from {event['source_ip']:16s} "
                  f"{event['log_count']:5d} logs  {event.get('first_seen','')[:19]}")
            if args.dry_run or not new:
                continue
            state = run_pipeline(event)
            persist_pipeline_result(state)
            processed += 1

        if args.dry_run:
            print("\n(dry run; nothing was written)")
        else:
            print(f"\nIngested {processed} event(s). Total events in DB: {Event.query.count()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
