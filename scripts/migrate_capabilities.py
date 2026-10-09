# -*- coding: utf-8 -*-
"""One-time migration for the capability-based access model.

Before: a user's authority came from the fixed role name ("manager"/"analyst")
via ROLE_DEFAULTS, with per-user overrides on top.

After: the role is a free-text job title only, and authority comes purely from
each user's capabilities (has_cap falls back to BASE_DEFAULTS, not the role).

To make sure nobody gains or loses access in the switch, this script MATERIALISES
every existing account's *current* effective capabilities into User.permissions,
computed with the OLD role-based logic. So a pre-existing "manager" keeps all
seven capabilities (it becomes an explicit admin), and an "analyst" keeps its
three base capabilities.

Run ONCE against the live database, then restart CyREN:

    venv\\Scripts\\python.exe scripts\\migrate_capabilities.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app                                                # noqa: E402
from app.models.db import (db, User, CAPABILITY_KEYS, BASE_DEFAULTS,      # noqa: E402
                           role_default)


def main():
    app = create_app()
    with app.app_context():
        users = User.query.all()
        if not users:
            print("no users — nothing to migrate.")
            return
        changed = 0
        for u in users:
            ov = u.permissions or {}
            # current effective caps under the OLD (role-based) logic
            old_eff = {k: (bool(ov[k]) if k in ov else role_default(u.role, k))
                       for k in CAPABILITY_KEYS}
            # store only the caps that differ from the new base default
            new_overrides = {k: v for k, v in old_eff.items()
                             if v != BASE_DEFAULTS[k]} or None
            admin = "ADMIN" if old_eff["manage_users"] else "     "
            caps = [k for k, v in old_eff.items() if v]
            print(f"  {admin} {u.username:16s} role={u.role:12s} caps={caps}")
            if new_overrides != (u.permissions or None):
                u.permissions = new_overrides
                changed += 1
        db.session.commit()
        admins = sum(1 for u in users if u.has_cap("manage_users"))
        print(f"\nmigrated {changed} user(s); {admins} administrator(s) hold manage_users.")
        if admins == 0:
            print("WARNING: no administrator! Check your data before restarting.")


if __name__ == "__main__":
    main()
