"""
Create or promote a SOC manager account from the command line.

This is the secure, standard way to bootstrap the FIRST manager account (the
same idea as Django's `createsuperuser`): it runs on the SERVER, with local
filesystem/database access -- it is NOT a web endpoint, so a remote attacker
can never reach it. The web application itself still refuses to hand out the
manager role: self-registration is disabled, and only an existing manager can
promote a user from the User Management page. After the first manager exists,
every other account is created from the UI.

That separation is exactly why this does not weaken application security: the
one path that can mint a manager requires operating-system access to the
server, and the network-facing paths cannot.

Usage:
    # create a new manager (password must meet the policy):
    python scripts/create_manager.py <username> <password> [full_name]

    # promote an existing user to manager (keeps their password):
    python scripts/create_manager.py --promote <username>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.models.db import db, User
from app.api.auth import _password_ok, PASSWORD_RULE


def main():
    args = sys.argv[1:]
    app = create_app()
    with app.app_context():
        if args and args[0] == "--promote":
            if len(args) < 2:
                sys.exit("usage: python scripts/create_manager.py --promote <username>")
            u = User.query.filter_by(username=args[1]).first()
            if not u:
                sys.exit(f"no user named {args[1]!r}")
            u.role = "manager"
            db.session.commit()
            print(f"promoted {u.username} to manager.")
            return

        if len(args) < 2:
            sys.exit("usage: python scripts/create_manager.py <username> <password> [full_name]")
        username, password = args[0], args[1]
        full_name = args[2] if len(args) > 2 else username
        if not _password_ok(password):
            sys.exit("password rejected: " + PASSWORD_RULE)

        u = User.query.filter_by(username=username).first()
        if u:
            u.role = "manager"
            u.set_password(password)
            u.full_name = full_name
            print(f"updated existing user {username!r} -> manager.")
        else:
            u = User(username=username, full_name=full_name, email="", role="manager")
            u.set_password(password)
            db.session.add(u)
            print(f"created manager {username!r}.")
        db.session.commit()


if __name__ == "__main__":
    main()
