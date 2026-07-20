"""
Remove events (and their reports/decisions/blocks) whose source IP is on the
SOURCE_IP_BLACKLIST. Run once after adding the blacklist to clean out noise
events that were ingested before it existed.

    venv/Scripts/python.exe scripts/purge_blacklisted_events.py --dry-run
    venv/Scripts/python.exe scripts/purge_blacklisted_events.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app                                   # noqa: E402
from app.models.db import db, Event, Report, BlockedIP, Decision, AttackChain  # noqa: E402
from app.services.siem_service import _is_blacklisted        # noqa: E402


def _is_noise(ip):
    """Blacklisted source, or one that could never be attributed."""
    return _is_blacklisted(ip) or not ip or ip == "unknown"


def main():
    dry = "--dry-run" in sys.argv
    app = create_app()
    with app.app_context():
        events = Event.query.order_by(Event.id).all()
        noise = [e for e in events if _is_noise(e.source_ip)]
        chains = [c for c in AttackChain.query.all() if _is_noise(c.source_ip)]
        print(f"{len(events)} events ({len(noise)} noise) and "
              f"{AttackChain.query.count()} chains ({len(chains)} noise)"
              f"{' (dry run)' if dry else ''}:\n")
        for e in noise:
            print(f"  event #{e.id} {e.rule or e.attack_type} from {e.source_ip} "
                  f"({e.log_count} logs)")
            if dry:
                continue
            for rep in Report.query.filter_by(event_id=e.id).all():
                p = rep.file_path or ""
                if p and not os.path.isabs(p):
                    p = os.path.join(os.path.dirname(os.path.dirname(
                        os.path.abspath(__file__))), p)
                if p and os.path.isfile(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
                db.session.delete(rep)
            Decision.query.filter_by(event_id=e.id).delete()
            BlockedIP.query.filter_by(event_id=e.id).delete()
            db.session.delete(e)
        for c in chains:
            print(f"  chain #{c.id} from {c.source_ip} ({c.stage_count} stages)")
            if not dry:
                db.session.delete(c)
        if not dry:
            db.session.commit()
            print(f"\nDeleted {len(noise)} event(s) + {len(chains)} chain(s). "
                  f"Remaining: {Event.query.count()} events, {AttackChain.query.count()} chains")
        else:
            print("\n(dry run; nothing deleted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
