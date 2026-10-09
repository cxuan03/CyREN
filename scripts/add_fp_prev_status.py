"""
One-time migration: add the false-positive redesign column to the events table.

    python scripts/add_fp_prev_status.py

Adds `fp_prev_status` (the state a false positive was marked FROM, so Undo can
restore blocked / awaiting / logged instead of a fixed state). Idempotent: safe
to run more than once.
"""
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import settings

COL = "fp_prev_status"
DDL = "ALTER TABLE events ADD COLUMN fp_prev_status VARCHAR(30)"


def _db_path() -> str:
    url = settings.DATABASE_URL
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "", 1)
    raise SystemExit("This migration only supports the SQLite DATABASE_URL.")


def main() -> None:
    path = _db_path()
    if not os.path.exists(path):
        raise SystemExit(f"Database not found at {path}")
    con = sqlite3.connect(path)
    cur = con.cursor()
    cols = {row[1] for row in cur.execute("PRAGMA table_info(events)")}
    if COL in cols:
        print(f"[migrate] events.{COL} already exists, nothing to do.")
    else:
        cur.execute(DDL)
        con.commit()
        print(f"[migrate] added events.{COL}")
    con.close()


if __name__ == "__main__":
    main()
