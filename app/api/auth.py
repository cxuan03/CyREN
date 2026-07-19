"""
Authentication routes: login, logout, and the login page.
"""
from datetime import datetime
from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from flask_login import login_user, logout_user, login_required

from app.models.db import db, User

auth = Blueprint("auth", __name__)


@auth.get("/login")
def login_page():
    return render_template("index.html")


@auth.post("/api/login")
def login():
    data = request.get_json(force=True)
    user = User.query.filter_by(username=data.get("username")).first()
    if user and user.is_active and user.check_password(data.get("password", "")):
        login_user(user)
        user.last_login = datetime.utcnow()
        db.session.commit()
        return jsonify({"ok": True, "user": user.to_dict()})
    return jsonify({"ok": False, "error": "invalid credentials"}), 401


@auth.post("/api/logout")
@login_required
def logout():
    logout_user()
    return jsonify({"ok": True})
