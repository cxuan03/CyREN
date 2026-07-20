"""
Re-run the investigation agent over events already in the database.

Useful after fixing or changing the LLM path: events analysed while the LLM
was unavailable still carry placeholder text, and their PDF reports were
written from it. This re-analyses those events and drops the stale reports so
they are regenerated from the new analysis on next view.

    venv/Scripts/python.exe scripts/reanalyse_events.py            # placeholders only
    venv/Scripts/python.exe scripts/reanalyse_events.py --all      # every non-low event
    venv/Scripts/python.exe scripts/reanalyse_events.py --dry-run
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app                              # noqa: E402
from app.models.db import db, Event, Report             # noqa: E402
from app.agents.investigation import _investigation     # noqa: E402

PLACEHOLDER_MARKERS = ("Placeholder analysis", "AI analysis unavailable")


def needs_reanalysis(event, force_all):
    if event.risk == "low":
        return False          # low-risk events intentionally skip the LLM
    summary = event.llm_summary or {}
    if force_all:
        return True
    if not summary:
        return True
    if summary.get("llm_error"):
        return True
    what = str(summary.get("what_happened", ""))
    return any(marker in what for marker in PLACEHOLDER_MARKERS)


def main():
    force_all = "--all" in sys.argv
    dry_run = "--dry-run" in sys.argv

    app = create_app()
    with app.app_context():
        print("LLM status:", _investigation.llm_status)
        if _investigation.groq is None:
            print("Refusing to run: the LLM is unavailable, so this would only "
                  "rewrite placeholders with placeholders.")
            print("Diagnose with: venv/Scripts/python.exe scripts/check_llm.py")
            return 1

        events = Event.query.order_by(Event.id).all()
        targets = [e for e in events if needs_reanalysis(e, force_all)]
        print(f"{len(events)} events in the database, {len(targets)} to re-analyse"
              f"{' (dry run)' if dry_run else ''}.\n")

        for e in targets:
            state = {
                "source_ip": e.source_ip, "dest_ip": e.dest_ip,
                "attack_type": e.attack_type, "rule": e.rule,
                "log_count": e.log_count, "risk": e.risk,
                "confidence": e.confidence,
                "raw_logs": e.raw_log_sample or [],
                "threat_intel": e.threat_intel or {},
                "asset": e.asset_info or {},
                "vulnerability": e.vuln_info or {},
            }
            print(f"  #{e.id} {e.attack_type} from {e.source_ip} ... ", end="", flush=True)
            if dry_run:
                print("would re-analyse")
                continue

            result = _investigation.run(state)
            summary = result.get("llm_summary") or {}
            if summary.get("llm_error"):
                print("FAILED:", summary["llm_error"])
                continue

            e.llm_summary = summary
            e.mitre_techniques = result.get("mitre_techniques") or e.mitre_techniques

            # the PDF was written from the old analysis: drop it so the next
            # view or download regenerates it from the new text
            removed = 0
            for rep in Report.query.filter_by(event_id=e.id).all():
                path = rep.file_path or ""
                if path and not os.path.isabs(path):
                    path = os.path.join(os.path.dirname(os.path.dirname(
                        os.path.abspath(__file__))), path)
                if path and os.path.isfile(path):
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                db.session.delete(rep)
                removed += 1
            db.session.commit()
            print(f"OK ({len(str(summary.get('what_happened','')))} chars"
                  f"{', dropped %d stale report' % removed if removed else ''})")

        print("\nDone. Open Incident Reports and view an event to regenerate its PDF.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
