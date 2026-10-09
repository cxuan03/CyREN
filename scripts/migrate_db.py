"""Idempotent schema migration for CyREN's SQLite DB.

create_all() builds the full schema for a FRESH database, but it never adds a
new column to a table that already exists. This script bridges that gap: it adds
any columns introduced after the initial schema, so an existing data/cyren.db can
be brought up to date without losing data. Safe to run repeatedly.

Usage:
    python scripts/migrate_db.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text
from app import create_app
from app.models.db import db

# table -> [(column, SQL type-with-default), ...] added after the initial schema
_ADDITIONS = {
    "users": [
        ("permissions", "TEXT"),                          # per-user capability overrides (JSON)
        ("must_change_password", "BOOLEAN DEFAULT 0"),    # force password change on first login
    ],
    "assets": [
        ("department", "VARCHAR(128)"),                   # owning department
    ],
    "events": [
        ("closed_at", "DATETIME"),                        # ticketing: resolved timestamp
        ("closed_by", "INTEGER"),
        ("close_note", "VARCHAR(500)"),
        ("ticket_status", "VARCHAR(16) DEFAULT 'open'"),  # open | in_progress | closed
        ("assigned_to", "INTEGER"),                       # responsible analyst
    ],
    "tickets": [
        ("excluded_event_ids", "TEXT"),                   # events the analyst detached (JSON)
    ],
    "ticket_comments": [
        ("parent_id", "INTEGER"),                         # threaded reply target
        ("edited_at", "DATETIME"),                        # last edit time
    ],
    "chat_messages": [
        ("parent_id", "INTEGER"),                         # reply target
        ("edited_at", "DATETIME"),
        ("deleted", "BOOLEAN DEFAULT 0"),
        ("pinned", "BOOLEAN DEFAULT 0"),
    ],
    "chat_groups": [
        ("left_ids", "TEXT"),                             # ex-members keeping read-only history (JSON)
    ],
}


def main():
    app = create_app()
    with app.app_context():
        insp = inspect(db.engine)
        existing_tables = set(insp.get_table_names())
        added = 0
        for table, cols in _ADDITIONS.items():
            if table not in existing_tables:
                continue   # create_all will build it fresh
            have = {c["name"] for c in insp.get_columns(table)}
            for name, ddl in cols:
                if name in have:
                    continue
                db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
                print(f"  + {table}.{name}")
                added += 1
        db.session.commit()
        print(f"Migration complete ({added} column(s) added).")


if __name__ == "__main__":
    main()
