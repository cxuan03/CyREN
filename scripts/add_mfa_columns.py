# -*- coding: utf-8 -*-
"""One-time migration: add the newer user columns to the users table.

Adds the second-factor columns (`security_question`, `security_answer_hash`) and
the self-registration flag (`pending_approval`) to the User model. SQLAlchemy's
create_all() only creates missing TABLES, never new COLUMNS on an existing table,
so this script ALTERs the live SQLite table for any column not there yet. It is
safe to run more than once (it checks first and skips columns that already exist).

Run ONCE against the live database, then restart CyREN:

    venv\\Scripts\\python.exe scripts\\add_mfa_columns.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text                       # noqa: E402
from app import create_app                         # noqa: E402
from app.models.db import db                       # noqa: E402

NEW_COLUMNS = {
    "security_question": "VARCHAR(200)",
    "security_answer_hash": "VARCHAR(256)",
    "pending_approval": "BOOLEAN DEFAULT 0",
}


def main():
    app = create_app()
    with app.app_context():
        existing = {row[1] for row in
                    db.session.execute(text("PRAGMA table_info(users)")).fetchall()}
        added = 0
        for col, coltype in NEW_COLUMNS.items():
            if col in existing:
                print(f"  {col}: already present, skipping.")
                continue
            db.session.execute(text(f"ALTER TABLE users ADD COLUMN {col} {coltype}"))
            print(f"  {col}: added.")
            added += 1
        db.session.commit()
        print(f"\ndone — {added} column(s) added. Second-factor storage is ready.")


if __name__ == "__main__":
    main()
