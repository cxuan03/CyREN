"""
Authentication routes: login, logout, registration, and their pages.
"""
import re
from datetime import datetime
from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user

from app.models.db import db, User

auth = Blueprint("auth", __name__)

PASSWORD_RULE = ("password must be at least 12 characters with uppercase, "
                 "lowercase, number and special character")


def _password_ok(pw: str) -> bool:
    return (len(pw) >= 12
            and re.search(r"[A-Z]", pw) is not None
            and re.search(r"[a-z]", pw) is not None
            and re.search(r"\d", pw) is not None
            and re.search(r"[^A-Za-z0-9]", pw) is not None)


@auth.get("/login")
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    return render_template("login.html")


@auth.get("/register")
def register_page():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    return render_template("register.html")


@auth.post("/api/register")
def register():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    full_name = (data.get("full_name") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    role = data.get("role") or "analyst"

    if not username or not full_name or not password:
        return jsonify({"ok": False, "error": "username, full name and password are required"}), 400
    if role not in ("analyst", "manager"):
        return jsonify({"ok": False, "error": "invalid role"}), 400
    if not _password_ok(password):
        return jsonify({"ok": False, "error": PASSWORD_RULE}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"ok": False, "error": "username already taken"}), 409

    user = User(username=username, full_name=full_name, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"ok": True, "user": user.to_dict()}), 201


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


@auth.post("/api/change-password")
@login_required
def change_password():
    data = request.get_json(force=True)
    if not current_user.check_password(data.get("current_password") or ""):
        return jsonify({"ok": False, "error": "current password is incorrect"}), 400
    new = data.get("new_password") or ""
    if not _password_ok(new):
        return jsonify({"ok": False, "error": PASSWORD_RULE}), 400
    current_user.set_password(new)
    db.session.commit()
    return jsonify({"ok": True})


@auth.post("/api/verify-password")
@login_required
def verify_password():
    """Re-authenticate before sensitive actions (e.g. unlocking thresholds)."""
    data = request.get_json(force=True)
    if current_user.check_password(data.get("password") or ""):
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "wrong password"}), 401


@auth.post("/api/profile")
@login_required
def update_profile():
    data = request.get_json(force=True)
    full_name = (data.get("full_name") or "").strip()
    if not full_name:
        return jsonify({"ok": False, "error": "full name is required"}), 400
    current_user.full_name = full_name
    current_user.email = (data.get("email") or "").strip()
    db.session.commit()
    return jsonify({"ok": True, "user": current_user.to_dict()})
