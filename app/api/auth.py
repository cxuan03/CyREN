"""
Authentication routes: login, logout, registration, and their pages.
"""
import re
import secrets
import time
from collections import defaultdict
from datetime import datetime
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user

from app.models.db import db, User, AuditLog

auth = Blueprint("auth", __name__)

PASSWORD_RULE = ("password must be at least 12 characters with uppercase, "
                 "lowercase, number and special character")

# ---- brute-force protection for /api/login ----
# In-memory failed-attempt tracker (per username + client IP). After
# LOGIN_MAX_FAILS failures within LOGIN_WINDOW seconds the key is locked for
# LOGIN_LOCK seconds. A successful login clears the counter. In-memory is fine
# for this single-process app; it resets on restart, which is acceptable.
LOGIN_MAX_FAILS = 5
LOGIN_WINDOW = 300      # count failures within the last 5 minutes
LOGIN_LOCK = 300        # lock for 5 minutes once the threshold is hit
_login_fails = defaultdict(list)   # key -> [failure timestamps]


def _login_key():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()
    data = request.get_json(silent=True) or {}
    return (data.get("username") or "?") + "|" + ip


def _login_locked(key) -> int:
    """Return seconds remaining on a lock, or 0 if not locked."""
    now = time.time()
    fails = [t for t in _login_fails.get(key, []) if now - t < LOGIN_WINDOW]
    _login_fails[key] = fails
    if len(fails) >= LOGIN_MAX_FAILS:
        return int(LOGIN_LOCK - (now - fails[-1])) or 1
    return 0


def _record_login_fail(key):
    _login_fails[key].append(time.time())


# ---- password reset via emailed one-time code (OTP) ----
# In-memory, single-process store: username -> {"otp", "exp", "tries"}. Codes are
# short-lived, so losing them on restart is acceptable (same trade-off as the
# login lockout above).
OTP_TTL = 600          # code valid for 10 minutes
OTP_MAX_TRIES = 5      # verification attempts before the code is burned
_otp_store = {}

# ---- second factor: pending security-question challenges ----
# After the password is verified, an account with a security question is NOT
# logged in yet: a short-lived challenge token is issued and the answer must be
# supplied to /api/login-verify to complete sign-in. In-memory, single-process
# (same trade-off as the stores above); token -> {"user_id", "exp", "tries"}.
MFA_TTL = 300          # 5 minutes to answer the security question
MFA_MAX_TRIES = 5      # wrong answers before the challenge is burned
_mfa_pending = {}


def _find_user(ident: str):
    """Look up a user by username or email (both matched case-sensitively)."""
    ident = (ident or "").strip()
    if not ident:
        return None
    return User.query.filter(
        (User.username == ident) | (User.email == ident)
    ).first()


def _password_ok(pw: str) -> bool:
    return (len(pw) >= 12
            and re.search(r"[A-Z]", pw) is not None
            and re.search(r"[a-z]", pw) is not None
            and re.search(r"\d", pw) is not None
            and re.search(r"[^A-Za-z0-9]", pw) is not None)


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _valid_email(email: str) -> bool:
    """Basic email-shape check (local@domain.tld, no spaces). An empty string is
    treated as 'valid' because email is optional; callers enforce presence."""
    email = (email or "").strip()
    return email == "" or bool(_EMAIL_RE.match(email))


def _generate_temp_password(length: int = 14) -> str:
    """A strong random one-time password for a newly-created account, generated
    with the cryptographic `secrets` module (not `random`). Guaranteed to satisfy
    _password_ok so the account is never seeded with a weak password."""
    import string
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    for _ in range(100):
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if _password_ok(pw):
            return pw
    # astronomically unlikely fallback: force one char of each required class
    rest = "".join(secrets.choice(alphabet) for _ in range(max(0, length - 4)))
    return "A" + "a" + "1" + "!" + rest


def _no_manager_yet() -> bool:
    """First-run: True until the first ADMIN account exists (one holding the
    'manage_users' capability). Registration is open only until then."""
    return not any(u.has_cap("manage_users") for u in User.query.all())


@auth.get("/login")
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    return render_template("login.html", setup_needed=_no_manager_yet())


def _email_change_page(title, body, ok=True):
    """Tiny standalone page for the confirm / reject links (no sign-in needed)."""
    color = "#0b8fa5" if ok else "#c0392b"
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>CyREN</title>"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"></head>"
        "<body style=\"margin:0;background:#0d1b2e;font-family:Arial,sans-serif;color:#e6eef8\">"
        "<div style=\"max-width:520px;margin:12vh auto;background:#16273f;border:1px solid #2b4364;"
        "border-radius:10px;padding:32px\">"
        f"<h2 style=\"margin:0 0 14px;color:{color}\">{title}</h2>"
        f"<p style=\"line-height:1.6\">{body}</p>"
        "<p style=\"margin-top:22px\"><a href=\"/login\" style=\"color:#8fd3e0\">Go to sign in</a></p>"
        "</div></body></html>")


@auth.get("/email-change/<token>/<action>")
def email_change_decide(token, action):
    """The account owner clicked Confirm or Not me in the email sent to the
    CURRENT address. No sign-in is needed (the owner may be locked out). The
    token must match a still-pending, unexpired request; anything else just
    shows 'expired' and changes nothing."""
    from itsdangerous import URLSafeTimedSerializer, BadData
    from flask import current_app
    from app.api.routes import EMAIL_CHANGE_TTL_MIN
    ser = URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="email-change")
    expired = _email_change_page(
        "This link has expired",
        "The request was already answered, withdrawn, or is older than "
        f"{EMAIL_CHANGE_TTL_MIN} minutes. Your account has not been changed. "
        "Ask your administrator to send a new request if it is still needed.", ok=False)
    try:
        data = ser.loads(token, max_age=EMAIL_CHANGE_TTL_MIN * 60)
    except BadData:
        return expired, 400
    u = db.session.get(User, data.get("uid"))
    if (not u or not u.pending_email or u.pending_email != data.get("new")
            or not u.pending_email_expires or u.pending_email_expires < datetime.utcnow()):
        return expired, 400
    requester = db.session.get(User, u.pending_email_by) if u.pending_email_by else None
    who = requester.username if requester else "a manager"
    if action == "confirm":
        from app.api.routes import _email_temp_password
        u.email = u.pending_email
        u.pending_email = None
        u.pending_email_by = None
        u.pending_email_expires = None
        temp = _generate_temp_password()
        u.set_password(temp)
        u.must_change_password = True
        db.session.add(AuditLog(user_id=u.id, action="email_change_confirmed",
                                detail=f"'{u.username}': email change confirmed by the owner (requested by {who}); one-time password sent"))
        # only the manager who asked for it is waiting for the answer
        if requester and requester.is_active:
            from app.models.db import Notification
            db.session.add(Notification(
                user_id=requester.id, kind="email_change_confirmed", ref_id=u.id,
                text=f"{u.username} confirmed the email change you requested"))
        db.session.commit()
        _email_temp_password(u, temp, lead="The email address on your CyREN account has been changed as you confirmed.")
        return _email_change_page(
            "Email change confirmed",
            "Your account now uses the new address. A one-time password has been sent "
            "there. Sign in with it and you will be asked to set a new password.")
    if action == "reject":
        u.pending_email = None
        u.pending_email_by = None
        u.pending_email_expires = None
        db.session.add(AuditLog(user_id=u.id, action="email_change_rejected",
                                detail=f"'{u.username}': email change REJECTED by the owner (requested by {who})"))
        # every manager hears about it: either the requester picked the wrong
        # account, or the requester's account is being misused
        from app.models.db import Notification
        for m in User.query.filter_by(is_active=True).all():
            if m.has_cap("manage_users"):
                db.session.add(Notification(
                    user_id=m.id, kind="email_change_rejected", ref_id=u.id,
                    text=f"{u.username} rejected an email change requested by {who}"))
        db.session.commit()
        return _email_change_page(
            "Change rejected",
            "Nothing on your account has been changed and the administrators have "
            "been notified. If this request was not made with your knowledge, sign "
            "in now and change your password, then report it to your administrator.",
            ok=False)
    return expired, 400


@auth.get("/register")
def register_page():
    # Two modes: first-run setup (no org yet) creates the organisation + admin;
    # once an org exists the page becomes a self-registration request (the new
    # account is created pending a manager's approval).
    return render_template("register.html", setup_needed=_no_manager_yet())


@auth.get("/api/register/company-status")
def register_company_status():
    """Anonymous check used by the register page for INSTANT feedback on the
    company field (is this name already registered?). This reveals nothing the
    login flow doesn't already reveal ('Organisation not found' vs proceeding)."""
    from app.models.db import Setting
    name = (request.args.get("name") or "").strip()
    stored = ((db.session.get(Setting, "company_name") or Setting()).value or "").strip()
    return jsonify({"ok": True,
                    "registered": bool(stored) and name.lower() == stored.lower()})


@auth.post("/api/register")
def register():
    """Two paths share this endpoint:
      1. FIRST-RUN setup (no organisation exists yet): the registrant names the
         organisation and becomes its first ADMINISTRATOR (full capabilities).
      2. SELF-REGISTRATION (organisation already exists): the registrant requests
         an account for that organisation. The account is created PENDING — it is
         inactive, has zero capabilities and cannot sign in until a manager
         approves it and assigns its permissions. This keeps account creation open
         without granting any access to the SOC's data before a human review."""
    data = request.get_json(force=True)
    company = (data.get("company") or "").strip()
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    if not company or not username or not email or not password:
        return jsonify({"ok": False, "error": "company, username, email and password are required"}), 400
    if not _valid_email(email):
        return jsonify({"ok": False, "error": "please enter a valid email address"}), 400
    if not _password_ok(password):
        return jsonify({"ok": False, "error": PASSWORD_RULE}), 400
    # usernames are unique ignoring capitalisation (mirrors create_user)
    if User.query.filter(db.func.lower(User.username) == username.lower()).first():
        return jsonify({"ok": False, "error": "username already taken"}), 409
    if User.email_taken(email):
        return jsonify({"ok": False, "error": "that email is already used by another account"}), 409

    from app.models.db import Setting, CAPABILITY_KEYS, Notification

    if _no_manager_yet():
        # -- path 1: first-run setup -> organisation + first administrator --
        row = db.session.get(Setting, "company_name") or Setting(key="company_name")
        row.value = company[:256]
        db.session.add(row)
        user = User(username=username, full_name=username, email=email,
                    role="SOC Manager",
                    permissions={k: True for k in CAPABILITY_KEYS})
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return jsonify({"ok": True, "mode": "setup", "user": user.to_dict()}), 201

    # -- path 2: self-registration into the existing organisation --
    stored = ((db.session.get(Setting, "company_name") or Setting()).value or "").strip()
    if company.lower() != stored.lower():
        # single tenant: an organisation is already registered on this system, so
        # a NEW company cannot be registered here. (Typing the registered
        # company's exact name instead submits an account request into it.)
        return jsonify({"ok": False, "error":
                        "This CyREN system already has a registered organisation, so a new "
                        "company cannot be registered. Check the company name — or use the "
                        "Sign in link below if you already have an account."}), 409
    if not email:
        return jsonify({"ok": False, "error":
                        "an email is required so a manager can reach you about approval"}), 400
    # created with NO access: inactive, pending, every capability explicitly off
    user = User(username=username, full_name=username, email=email,
                role="(pending approval)", is_active=False, pending_approval=True,
                permissions={k: False for k in CAPABILITY_KEYS})
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    db.session.add(AuditLog(user_id=None, action="user_selfregistered",
                            detail=f"'{username}' requested an account (awaiting approval)"))
    # let every active administrator know there is someone to review
    for m in User.query.all():
        if m.is_active and m.has_cap("manage_users"):
            db.session.add(Notification(
                user_id=m.id, kind="account_request", ref_id=user.id,
                text=f"{username} requested an account — review in User Management"))
    db.session.commit()
    return jsonify({"ok": True, "mode": "pending",
                    "message": ("Account requested. A manager will review and approve it — "
                                "you'll be able to sign in once it's approved.")}), 201


@auth.post("/api/login")
def login():
    key = _login_key()
    locked = _login_locked(key)
    if locked:
        # show minutes once it's a minute or more (e.g. "about 5 minutes" instead
        # of "299 seconds"); keep seconds only for the final sub-minute stretch.
        if locked >= 60:
            mins = -(-locked // 60)   # round up
            when = f"about {mins} minute{'s' if mins != 1 else ''}"
        else:
            when = f"{locked} second{'s' if locked != 1 else ''}"
        # retry_after lets the sign-in page show a live mm:ss countdown; the text
        # message stays as a no-JS fallback.
        return jsonify({"ok": False, "retry_after": locked, "error":
                        f"too many failed attempts, try again in {when}"}), 429
    data = request.get_json(force=True)
    # organisation gate: the sign-in names the organisation. If none is set up
    # yet, or the typed name does not match, send them to register to set it up /
    # correct it (a wrong company is not counted as a failed password attempt).
    from app.models.db import Setting
    company = (data.get("company") or "").strip()
    stored = ((db.session.get(Setting, "company_name") or Setting()).value or "").strip()
    if not stored:
        # No organisation exists yet -> send them to first-run registration.
        return jsonify({"ok": False, "redirect": "/register",
                        "error": "No organisation is set up yet — redirecting you to registration…"}), 401
    if company.lower() != stored.lower():
        # An organisation exists but this name does not match it: treat it as an
        # unregistered company and send them to the register page (which offers a
        # "Sign in" link back, and refuses to re-register an existing company).
        # The typed name is carried over so the form is prefilled.
        # Record the mismatch in the audit / login history (attributed to the
        # account if the username exists); a wrong company is NOT counted toward
        # the failed-attempt lockout (that lock is for password guessing only).
        _wc_user = User.query.filter_by(username=(data.get("username") or "").strip()).first()
        db.session.add(AuditLog(user_id=(_wc_user.id if _wc_user else None), action="login_failed",
                                detail=f"'{(data.get('username') or '').strip()}' - wrong company name"))
        db.session.commit()
        from urllib.parse import quote
        return jsonify({"ok": False,
                        "redirect": "/register?company=" + quote(company),
                        "error": "Organisation not found — taking you to registration. "
                                 "Use the Sign in link there to come back."}), 401
    attempted = (data.get("username") or "").strip()
    user = User.query.filter_by(username=attempted).first()
    if user and user.is_active and user.check_password(data.get("password", "")):
        _login_fails.pop(key, None)   # clear the counter on success
        # Second factor: if the account has a security question set, do NOT sign
        # in yet. Issue a short-lived challenge; the answer completes sign-in via
        # /api/login-verify. The password was correct, so this is a second step.
        if user.mfa_enabled():
            token = secrets.token_urlsafe(24)
            _mfa_pending[token] = {"user_id": user.id, "exp": time.time() + MFA_TTL, "tries": 0}
            return jsonify({"ok": False, "mfa": True, "token": token,
                            "question": user.security_question})
        login_user(user)
        session.permanent = True      # subject the session to the idle-timeout lifetime
        user.last_login = datetime.utcnow()
        # every successful sign-in is recorded too (shown with the failed ones
        # in My Profile > Login History; kept out of the main audit page)
        db.session.add(AuditLog(user_id=user.id, action="login_success",
                                detail=f"'{user.username}' signed in"))
        db.session.commit()
        return jsonify({"ok": True, "user": user.to_dict()})
    # self-registered but not yet approved: if the password is right, tell them
    # plainly they are awaiting approval (they know they registered, so this is
    # not sensitive account enumeration). A wrong password still falls through.
    if user and user.pending_approval and user.check_password(data.get("password", "")):
        return jsonify({"ok": False, "error":
                        "Your account is awaiting approval by a manager — you'll be able "
                        "to sign in once it's approved."}), 403
    # record the failed attempt for the audit trail (wrong password, disabled or
    # unknown account). Attributed to the account if the username exists.
    _record_login_fail(key)
    if user and not user.is_active:
        reason = "account disabled"
    elif user:
        reason = "wrong password"
    else:
        reason = "unknown username"
    db.session.add(AuditLog(user_id=(user.id if user else None), action="login_failed",
                            detail=f"'{attempted}' - {reason}"))
    # if THIS failure just tripped the lockout threshold, record the lockout once
    # (while locked, later requests are refused above and never reach here, so
    # the in-window count lands on exactly LOGIN_MAX_FAILS at the trigger).
    in_window = [t for t in _login_fails.get(key, []) if time.time() - t < LOGIN_WINDOW]
    if len(in_window) == LOGIN_MAX_FAILS:
        db.session.add(AuditLog(user_id=(user.id if user else None), action="login_locked",
                                detail=f"'{attempted}' - locked after {LOGIN_MAX_FAILS} "
                                       f"failed attempts ({LOGIN_LOCK // 60} min)"))
    db.session.commit()
    return jsonify({"ok": False, "error": "invalid credentials"}), 401


@auth.post("/api/login-verify")
def login_verify():
    """Second step of sign-in: verify the answer to the account's security
    question against a challenge issued by /api/login, then complete the login."""
    data = request.get_json(force=True)
    token = (data.get("token") or "").strip()
    answer = data.get("answer") or ""
    rec = _mfa_pending.get(token)
    if not rec or time.time() > rec["exp"]:
        _mfa_pending.pop(token, None)
        return jsonify({"ok": False, "expired": True,
                        "error": "your sign-in session expired — please sign in again"}), 400
    rec["tries"] += 1
    if rec["tries"] > MFA_MAX_TRIES:
        _mfa_pending.pop(token, None)
        return jsonify({"ok": False, "expired": True,
                        "error": "too many incorrect answers — please sign in again"}), 429
    user = db.session.get(User, rec["user_id"])
    if not user or not user.is_active:
        _mfa_pending.pop(token, None)
        return jsonify({"ok": False, "expired": True,
                        "error": "this account is no longer available"}), 400
    if not user.check_security_answer(answer):
        db.session.add(AuditLog(user_id=user.id, action="login_failed",
                                detail=f"'{user.username}' - wrong security answer"))
        db.session.commit()
        return jsonify({"ok": False, "error": "that answer is not correct"}), 401
    # answer correct -> complete the sign-in
    _mfa_pending.pop(token, None)
    login_user(user)
    session.permanent = True
    user.last_login = datetime.utcnow()
    db.session.add(AuditLog(user_id=user.id, action="login_success",
                            detail=f"'{user.username}' signed in (2-step verified)"))
    db.session.commit()
    return jsonify({"ok": True, "user": user.to_dict()})


@auth.get("/api/security-question")
@login_required
def get_security_question():
    """Current user's second-factor status (for the My Profile security card)."""
    return jsonify({"ok": True, "enabled": current_user.mfa_enabled(),
                    "question": current_user.security_question or ""})


@auth.post("/api/security-question")
@login_required
def set_security_question():
    """Enable, change or disable the current user's security question. Changing
    the second factor always requires the account password (so a walked-up open
    session cannot silently add or remove it)."""
    data = request.get_json(force=True)
    if not current_user.check_password(data.get("password") or ""):
        return jsonify({"ok": False, "error": "current password is incorrect"}), 400
    if data.get("disable"):
        current_user.security_question = None
        current_user.security_answer_hash = None
        db.session.commit()
        return jsonify({"ok": True, "enabled": False})
    question = (data.get("question") or "").strip()
    answer = (data.get("answer") or "").strip()
    if not question or not answer:
        return jsonify({"ok": False, "error": "choose a question and enter an answer"}), 400
    if len(answer) < 2:
        return jsonify({"ok": False, "error": "your answer is too short"}), 400
    current_user.security_question = question[:200]
    current_user.set_security_answer(answer)
    db.session.commit()
    return jsonify({"ok": True, "enabled": True, "question": current_user.security_question})


@auth.post("/api/forgot-password")
def forgot_password():
    """Step 1 of reset: email a one-time code to the account's address. Requires
    BOTH the username AND the email on file to match the same account; per user,
    a mismatch is rejected with an explicit error instead of the anti-enumeration
    generic message."""
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    user = User.query.filter_by(username=username).first() if username else None
    email_matches = bool(user and user.email and email
                         and user.email.strip().lower() == email.lower())
    if not (user and user.is_active and email_matches):
        # audit the denied reset request (attributed to the account when the
        # username is valid, so it also surfaces in that user's login history)
        db.session.add(AuditLog(user_id=(user.id if user else None), action="password_reset_failed",
                                detail=f"'{username}' - password-reset request denied "
                                       f"(username/email mismatch)"))
        db.session.commit()
        return jsonify({"ok": False,
                        "error": "Username and email do not match. Check both and try again."}), 400
    otp = f"{secrets.randbelow(1000000):06d}"
    _otp_store[user.username] = {"otp": otp, "exp": time.time() + OTP_TTL, "tries": 0}
    from app.services.email_service import send_alert_email
    html = (
        "<div style=\"font-family:Arial,sans-serif;max-width:520px;margin:auto\">"
        "<h2 style=\"color:#0d2c50\">CyREN password reset</h2>"
        "<p>Use this one-time code to reset your password:</p>"
        f"<p style=\"font-size:30px;font-weight:800;letter-spacing:6px;color:#0d2c50\">{otp}</p>"
        "<p>The code expires in 10 minutes. If you did not request a reset, "
        "you can safely ignore this email.</p></div>")
    # send_alert_email logs the code if SMTP is not configured, so the flow
    # is still testable before email is set up.
    send_alert_email(to=user.email, subject="[CyREN] Your password reset code", html_body=html)
    return jsonify({"ok": True, "message": "A reset code has been emailed to the address on file."})


@auth.post("/api/reset-password")
def reset_password():
    """Step 2 of reset: verify the code and set a new password."""
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    user = User.query.filter_by(username=username).first() if username else None
    otp = (data.get("otp") or "").strip()
    new = data.get("new_password") or ""
    rec = _otp_store.get(user.username) if user else None
    if not user or not rec:
        return jsonify({"ok": False, "error": "invalid or expired code"}), 400
    if time.time() > rec["exp"]:
        _otp_store.pop(user.username, None)
        return jsonify({"ok": False, "error": "the code has expired, request a new one"}), 400
    rec["tries"] += 1
    if rec["tries"] > OTP_MAX_TRIES:
        _otp_store.pop(user.username, None)
        return jsonify({"ok": False, "error": "too many attempts, request a new code"}), 429
    if not secrets.compare_digest(otp, rec["otp"]):
        return jsonify({"ok": False, "error": "incorrect code"}), 400
    if not _password_ok(new):
        return jsonify({"ok": False, "error": PASSWORD_RULE}), 400
    user.set_password(new)
    # They just chose a fresh password themselves, so don't force another
    # change on login (that flag is only for manager-issued temp passwords).
    user.must_change_password = False
    db.session.add(AuditLog(user_id=user.id, action="password_reset",
                            detail=f"'{user.username}' reset their password via forgot-password"))
    db.session.commit()
    _otp_store.pop(user.username, None)
    return jsonify({"ok": True})


@auth.post("/api/logout")
@login_required
def logout():
    logout_user()
    return jsonify({"ok": True})


@auth.post("/api/change-password")
@login_required
def change_password():
    data = request.get_json(force=True)
    # On a FORCED first-login change the user already authenticated with the temp
    # password moments ago, so they need not re-enter it; otherwise the current
    # password must be verified.
    if not current_user.must_change_password:
        if not current_user.check_password(data.get("current_password") or ""):
            return jsonify({"ok": False, "error": "current password is incorrect"}), 400
    new = data.get("new_password") or ""
    if not _password_ok(new):
        return jsonify({"ok": False, "error": PASSWORD_RULE}), 400
    if current_user.check_password(new):
        return jsonify({"ok": False, "error": "please choose a password different from the temporary one"}), 400
    current_user.set_password(new)
    current_user.must_change_password = False   # first-login requirement satisfied
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
    from app.models.db import Setting, AuditLog
    data = request.get_json(force=True)
    changes = []

    # email
    email = (data.get("email") or "").strip()
    if not _valid_email(email):
        return jsonify({"ok": False, "error": "please enter a valid email address"}), 400
    if User.email_taken(email, exclude_id=current_user.id):
        return jsonify({"ok": False, "error": "that email is already used by another account"}), 409
    if email != (current_user.email or ""):
        changes.append("email")
    current_user.email = email

    # username (this is also the sign-in name; full_name mirrors it)
    if "username" in data:
        uname = (data.get("username") or "").strip()
        if not uname:
            return jsonify({"ok": False, "error": "username cannot be empty"}), 400
        if uname.lower() != current_user.username.lower() and \
                User.query.filter(db.func.lower(User.username) == uname.lower()).first():
            return jsonify({"ok": False, "error": "username already taken"}), 409
        if uname != current_user.username:
            changes.append(f"username '{current_user.username}' -> '{uname}'")
            current_user.username = uname
            current_user.full_name = uname

    # role — a free-text job-title LABEL. It does NOT grant any permission
    # (authority comes from capabilities), but a change is audited and shows in
    # User Management.
    if "role" in data:
        role = (data.get("role") or "").strip()[:48]
        if not role:
            return jsonify({"ok": False, "error": "role cannot be empty"}), 400
        if role != (current_user.role or ""):
            changes.append(f"role -> {role}")
            current_user.role = role

    # organisation name (a global Setting used at sign-in for everyone)
    company_val = None
    if "company" in data:
        company = (data.get("company") or "").strip()
        if not company:
            return jsonify({"ok": False, "error": "organisation name cannot be empty"}), 400
        row = db.session.get(Setting, "company_name") or Setting(key="company_name")
        if (row.value or "") != company:
            changes.append(f"organisation -> {company}")
            row.value = company[:256]
            db.session.add(row)

    if changes:
        db.session.add(AuditLog(user_id=current_user.id, action="profile_updated",
                                detail=f"'{current_user.username}' updated profile: {', '.join(changes)}"))
    db.session.commit()
    company_val = ((db.session.get(Setting, "company_name") or Setting()).value or "")
    return jsonify({"ok": True, "user": current_user.to_dict(), "company_name": company_val})
