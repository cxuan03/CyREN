# -*- coding: utf-8 -*-
"""Reset CyREN's detection data for a clean demo / a fresh attack run.

Clears everything the pipeline produces — events, attack chains, tickets (and
their comments / activity / links), firewall blocks, generated reports,
notifications, decisions, chain predictions, event notes — and lifts the real
firewall blocks so the host firewall matches.

KEEPS: users, assets, settings/thresholds, chat, and the audit log (pass
--wipe-audit to clear the audit log too).

MTTR and every dashboard figure are computed LIVE from this data, so they reset
to empty after this — that is expected for a fresh run. Numbers you already
recorded (screenshots, report figures) are NOT affected.

    venv\\Scripts\\python.exe scripts\\reset_lab_data.py            # asks to confirm
    venv\\Scripts\\python.exe scripts\\reset_lab_data.py --yes      # no prompt
    venv\\Scripts\\python.exe scripts\\reset_lab_data.py --yes --wipe-audit
"""
import sys

sys.path.insert(0, ".")
from datetime import datetime                                    # noqa: E402
from app import create_app                                      # noqa: E402
from app.models.db import (db, Event, AttackChain, BlockedIP, Report,        # noqa: E402
                           Decision, EventNote, ChainPrediction, Ticket,
                           TicketComment, TicketActivity, Notification, AuditLog,
                           Setting)


def main():
    yes = "--yes" in sys.argv or "-y" in sys.argv
    wipe_audit = "--wipe-audit" in sys.argv
    reingest = "--reingest" in sys.argv     # re-process the OLD logs too
    purge_es = "--purge-es" in sys.argv     # DELETE the old logs from Elasticsearch

    app = create_app()
    with app.app_context():
        counts = {
            "events": Event.query.count(),
            "attack_chains": AttackChain.query.count(),
            "tickets": Ticket.query.count(),
            "firewall_blocks (active)": BlockedIP.query.filter_by(active=True).count(),
            "reports": Report.query.count(),
            "notifications": Notification.query.count(),
        }
        print("CyREN lab reset — this will DELETE the detection data:")
        for k, v in counts.items():
            print(f"    {k:28} {v}")
        print("  KEEPS: users, assets, settings, chat" +
              (", audit log" if not wipe_audit else "  (AUDIT LOG WILL ALSO BE WIPED)"))

        if not yes:
            ans = input("\nProceed? Type 'reset' to confirm: ").strip().lower()
            if ans != "reset":
                print("Aborted — nothing was deleted.")
                return

        # 1) lift the real firewall blocks so iptables/ipset matches the DB
        lifted = 0
        try:
            from app.agents.response import response_agent
            for b in BlockedIP.query.filter_by(active=True).all():
                try:
                    response_agent.unblock_ip(b.ip)
                    lifted += 1
                except Exception as exc:
                    print(f"  ! could not unblock {b.ip}: {exc}")
        except Exception as exc:
            print(f"  ! response agent unavailable, firewall not touched: {exc}")

        # 2) clear the child rows first, then the parents (FK-safe order)
        for model in (TicketComment, TicketActivity, Notification, Decision,
                      EventNote, ChainPrediction, Report, BlockedIP):
            model.query.delete()
        db.session.execute(db.text("DELETE FROM ticket_events"))
        Ticket.query.delete()
        Event.query.delete()
        AttackChain.query.delete()
        if wipe_audit:
            AuditLog.query.delete()

        # CRITICAL: move the ingest watermark to NOW so the poller stops
        # re-ingesting the OLD logs still in Elasticsearch. Without this, the
        # next poll rebuilds everything from the existing filebeat logs — which
        # is why "I reset but the firewall/email came back without attacking".
        if reingest:
            Setting.set("ingest_since", None)
            wm_note = "watermark CLEARED (--reingest): old logs WILL be re-processed"
        else:
            now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
            Setting.set("ingest_since", now_iso)
            wm_note = f"ingest watermark set to {now_iso} UTC — only NEW logs will be ingested"
        db.session.commit()

        # optional: actually delete the old telemetry from Elasticsearch
        purged = None
        if purge_es and not reingest:
            try:
                from app.services.siem_service import siem_service
                cutoff = Setting.get("ingest_since")
                purged = siem_service.purge_filebeat_before(cutoff)
            except Exception as exc:
                print(f"  ! ES purge failed: {exc}")

        print(f"\nDone. Firewall blocks lifted: {lifted}.")
        print(f"      {wm_note}.")
        if purged is not None:
            print(f"      Elasticsearch: deleted {purged} old log document(s).")
        print("The detection data is cleared. Run a NEW attack and CyREN will")
        print("rebuild fresh events, chains and tickets from it.")


if __name__ == "__main__":
    main()
