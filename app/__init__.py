"""
Flask application factory for CyREN.

    from app import create_app
    app = create_app()
"""
import os
from flask import Flask, render_template
from flask_login import LoginManager
from flask_cors import CORS

from config.settings import settings
from app.models.db import db, User


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = settings.SECRET_KEY

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
    CORS(app, supports_credentials=True)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login_page"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

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
        return render_template("index.html")

    with app.app_context():
        db.create_all()

    return app
