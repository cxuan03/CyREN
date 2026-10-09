"""
Flask application factory for CyREN.

    from app import create_app
    app = create_app()
"""
import os
from flask import Flask, render_template, redirect, url_for, request, jsonify, session
from flask_login import LoginManager, current_user
from flask_cors import CORS

from config.settings import settings
from app.models.db import db, User, Setting


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = settings.SECRET_KEY
    # Session cookie hardening: not readable by JS, only sent same-site.
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # Idle auto-logout: a signed-in session expires after this many minutes of
    # inactivity. Flask slides the expiry on each request, so it is an idle
    # timeout, not an absolute one. Requires session.permanent (set at login).
    from datetime import timedelta
    app.permanent_session_lifetime = timedelta(minutes=settings.IDLE_TIMEOUT_MINUTES)

    # Resolve a relative sqlite path against the project root so the app can be
    # started from any working directory.
    db_url = settings.DATABASE_URL
    if db_url.startswith("sqlite:///") and not db_url.startswith("sqlite:////"):
        rel = db_url.replace("sqlite:///", "", 1)
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        abs_path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        db_url = "sqlite:///" + abs_path
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    # CORS: the UI is served by Flask itself (same-origin), so credentialed
    # cross-origin requests are only allowed from CyREN's own origins. This
    # replaces the previous wildcard, which reflected ANY origin with the
    # session cookie attached. Extra origins can be added via CORS_ORIGINS.
    CORS(app, supports_credentials=True, origins=settings.CORS_ORIGINS)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login_page"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        # Treat a disabled OR deleted account as logged-out: return None so the
        # very next request from that user is unauthenticated. This is the point
        # that actually enforces a manager's "disable"/"delete" — as soon as the
        # row is gone or is_active flips to False, the session stops resolving to
        # a user. The unauthorized_handler below turns that into a clear message.
        u = User.query.get(int(user_id))
        if u is None or not u.is_active:
            return None
        return u

    @login_manager.unauthorized_handler
    def _unauthorized():
        """Where an unauthenticated request lands. If the browser still carries a
        session for a user that no longer resolves (disabled or deleted), say so
        specifically; otherwise it's an ordinary expired/absent session."""
        stale = bool(session.get("_user_id"))   # a user WAS signed in, now invalid
        if request.path.startswith("/api/"):
            return jsonify({"error": "account_unavailable" if stale else "unauthorized"}), 401
        if stale:
            return redirect(url_for("auth.login_page", account="disabled"))
        return redirect(url_for("auth.login_page"))

    # ensure enrichment tables (Asset, Vulnerability) are registered
    from app.enrichment.asset_assessment import Asset          # noqa: F401
    from app.enrichment.vuln_assessment import Vulnerability   # noqa: F401

    # blueprints
    from app.api.routes import api
    from app.api.auth import auth
    app.register_blueprint(api)
    app.register_blueprint(auth)

    @app.get("/")
    def home():
        if not current_user.is_authenticated:
            # a leftover session for a now-disabled/deleted account -> explain it
            if session.get("_user_id"):
                return redirect(url_for("auth.login_page", account="disabled"))
            return redirect(url_for("auth.login_page"))
        return render_template(
            "index.html",
            idle_timeout=settings.IDLE_TIMEOUT_MINUTES,
            company_name=Setting.get("company_name", ""),
        )

    with app.app_context():
        db.create_all()
        # columns added after a table first shipped: SQLite gets them here
        # (create_all only creates missing TABLES, never missing columns)
        from sqlalchemy import inspect, text
        insp = inspect(db.engine)
        if "report_notes" in insp.get_table_names():
            have = {c["name"] for c in insp.get_columns("report_notes")}
            for name, ddl in (("image_path", "VARCHAR(300)"), ("deleted_at", "DATETIME"),
                              ("deleted_by", "INTEGER"), ("edited_at", "DATETIME")):
                if name not in have:
                    db.session.execute(text(f"ALTER TABLE report_notes ADD COLUMN {name} {ddl}"))
            db.session.commit()
        if "users" in insp.get_table_names():
            have = {c["name"] for c in insp.get_columns("users")}
            for name, ddl in (("pending_email", "VARCHAR(128)"), ("pending_email_by", "INTEGER"),
                              ("pending_email_expires", "DATETIME")):
                if name not in have:
                    db.session.execute(text(f"ALTER TABLE users ADD COLUMN {name} {ddl}"))
            db.session.commit()
        if "assets" in insp.get_table_names():
            have = {c["name"] for c in insp.get_columns("assets")}
            if "description" not in have:
                db.session.execute(text("ALTER TABLE assets ADD COLUMN description VARCHAR(300)"))
            db.session.commit()

    return app
