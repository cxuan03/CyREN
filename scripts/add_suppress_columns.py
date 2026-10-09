"""Add the alert-suppression columns to the events table (idempotent).

    python scripts/add_suppress_columns.py

Adds events.suppressed_until, events.suppress_reason, events.suppress_hits and
events.suppress_notified so a dismissed event can suppress repeats of the same
source+rule until a date. Safe to run more than once. Mirrors the additive
pattern of scripts/add_note_tombstone_columns.py.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.models.db import db


# column name -> the DDL type used in the ADD COLUMN
_COLS = {
    "suppressed_until": "DATETIME",
    "suppress_reason": "VARCHAR(200)",
    "suppress_hits": "INTEGER DEFAULT 0",
    "suppress_notified": "BOOLEAN DEFAULT 0",
}


def _existing(table):
    rows = db.session.execute(db.text("PRAGMA table_info(%s)" % table)).fetchall()
    return {r[1] for r in rows}


def main():
    app = create_app()
    with app.app_context():
        have = _existing("events")
        added = []
        for col, ddl in _COLS.items():
            if col not in have:
                db.session.execute(db.text("ALTER TABLE events ADD COLUMN %s %s" % (col, ddl)))
                added.append(col)
        db.session.commit()
        if added:
            print("added events columns:", ", ".join(added))
        else:
            print("nothing to add; events already has all suppression columns")


if __name__ == "__main__":
    main()
