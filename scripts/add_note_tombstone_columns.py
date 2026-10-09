# -*- coding: utf-8 -*-
"""One-time migration: add the edit/soft-delete columns to notes and comments.

Event notes and ticket comments are now edited in place (with an "edited"
marker) and deleted as a TOMBSTONE (the row stays, showing who deleted it and
when) instead of being removed. SQLAlchemy's create_all() only creates missing
TABLES, never new COLUMNS on an existing table, so this script ALTERs the live
SQLite tables for any column not there yet. Safe to run more than once.

Run ONCE against the live database, then restart CyREN:

    venv\\Scripts\\python.exe scripts\\add_note_tombstone_columns.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text                       # noqa: E402
from app import create_app                         # noqa: E402
from app.models.db import db                       # noqa: E402

NEW_COLUMNS = {
    "event_notes": {
        "edited_at": "DATETIME",
        "deleted_at": "DATETIME",
        "deleted_by": "INTEGER",
    },
    "ticket_comments": {
        "deleted_at": "DATETIME",
        "deleted_by": "INTEGER",
    },
}


def main():
    app = create_app()
    with app.app_context():
        added = 0
        for table, cols in NEW_COLUMNS.items():
            existing = {row[1] for row in
                        db.session.execute(text(f"PRAGMA table_info({table})")).fetchall()}
            for col, coltype in cols.items():
                if col in existing:
                    print(f"  {table}.{col}: already present, skipping.")
                    continue
                db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}"))
                print(f"  {table}.{col}: added.")
                added += 1
        db.session.commit()
        print(f"\ndone - {added} column(s) added. Note edit/delete tombstones are ready.")


if __name__ == "__main__":
    main()
