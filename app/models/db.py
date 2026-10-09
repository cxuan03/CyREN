"""
Database models for CyREN.

The schema mirrors the interfaces described in Chapter 3:
  - Event         -> All Events, Human Approval, Event Detail
  - AttackChain   -> Attack Chain page
  - BlockedIP     -> Firewall Blocks page
  - Report        -> Incident Reports page
  - User          -> User Management, My Profile, login
  - Decision      -> feeds continuous learning + My Profile "Your Activity"

Note: the system uses Elasticsearch and ChromaDB as its primary data stores
for raw logs and the knowledge base. This relational database only holds the
*aggregated events* and the *operational state* the dashboard works with,
which is why an ER model is appropriate here even though the wider system is
not relational.
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


# ---------------------------------------------------------------------------
# Capability model (flexible, per-user permissions)
# ---------------------------------------------------------------------------
# A user's role ("analyst" / "manager") sets the DEFAULT answer for each
# capability. A manager can then override individual capabilities per user
# (e.g. let one senior analyst manage assets without making them a full
# manager). Overrides are stored on User.permissions as {cap: bool}; only the
# capabilities that DIFFER from the role default are stored, so a later role
# change automatically re-bases the untouched ones.
# Permissions are page-centric: ticking one shows its page(s) AND lets the user
# act on them. 'view' is the read master — it unlocks the monitoring pages, each
# of which is separately grantable via VIEW_PAGES below. The other permissions
# each unlock one page/area and its actions. (The stored keys are unchanged, so
# existing permission records keep working; only the labels are page-worded.)
CAPABILITIES = [
    {"key": "view",              "label": "View events & attack chains",
     "desc": "Read-only access to the monitoring pages (choose which below)."},
    {"key": "approve_events",    "label": "Tickets",
     "desc": "Approve or dismiss events and work case tickets."},
    {"key": "block_ips",         "label": "Firewall Blocks",
     "desc": "See the firewall block list and block or unblock source IPs."},
    {"key": "manage_assets",     "label": "Asset Inventory",
     "desc": "Add, edit or remove entries in the asset inventory."},
    {"key": "change_thresholds", "label": "Change risk thresholds",
     "desc": "Move the risk thresholds and change the AI automation level."},
    {"key": "retrain_model",     "label": "Retrain the model",
     "desc": "Start a retraining run of the triage model."},
    {"key": "manage_users",      "label": "User Management",
     "desc": "Manage user accounts and their permissions."},
]
CAPABILITY_KEYS = [c["key"] for c in CAPABILITIES]

# The read pages unlocked by 'view', each separately grantable. Keys match the
# frontend page ids (data-p / go()). Granting 'view' with no explicit view_pages
# list means ALL of these are visible (keeps existing accounts unchanged).
VIEW_PAGES = [
    {"key": "dash",    "label": "Dashboard"},
    {"key": "alerts",  "label": "All Events"},
    {"key": "rawlogs", "label": "Raw Logs"},
    {"key": "chain",   "label": "Attack Chains"},
    {"key": "reports", "label": "Reports"},
    {"key": "audit",   "label": "Audit Logs"},
]
VIEW_PAGE_KEYS = [p["key"] for p in VIEW_PAGES]
# What a manager-created account is PRE-TICKED with: monitoring + tickets, but
# NOT Audit Logs, NOT Firewall Blocks, NOT the admin areas (granted explicitly).
DEFAULT_VIEW_PAGES = {k: (k != "audit") for k in VIEW_PAGE_KEYS}

# Per-role defaults (mirrors the read-only matrix shown in the UI).
ROLE_DEFAULTS = {
    "analyst": {"view": True, "approve_events": True, "block_ips": True,
                "manage_assets": False, "change_thresholds": False,
                "retrain_model": False, "manage_users": False},
    "manager": {k: True for k in CAPABILITY_KEYS},
}


def role_default(role, cap):
    return ROLE_DEFAULTS.get(role, ROLE_DEFAULTS["analyst"]).get(cap, False)


# The FALLBACK capabilities for any cap a user's permissions dict does not
# mention. This is NOT the new-account default (see DEFAULT_NEW_CAPS) — it is the
# baseline that existing accounts with a partial or empty permissions record run
# on, so it must stay stable or those accounts would silently lose access. The
# role/title is a free-text LABEL only; real authority comes from capabilities,
# so "admin" simply means holding `manage_users`. ROLE_DEFAULTS above is kept
# only for the one-time migration of pre-existing accounts.
BASE_DEFAULTS = {"view": True, "approve_events": True, "block_ips": True,
                 "manage_assets": False, "change_thresholds": False,
                 "retrain_model": False, "manage_users": False}

# What a brand-new account is PRE-TICKED with when a manager adds/approves it: a
# plain operator who can read the monitoring pages and work tickets, but NOT
# block at the firewall, NOT see the audit log, and none of the admin areas.
# (Firewall Blocks differs from BASE_DEFAULTS on purpose — an operator gets it
# only when a manager grants it — so this is stored as an explicit override.)
DEFAULT_NEW_CAPS = {"view": True, "approve_events": True, "block_ips": False,
                    "manage_assets": False, "change_thresholds": False,
                    "retrain_model": False, "manage_users": False}


def has_other_admin(exclude_user_id):
    """True if some OTHER active account still holds 'manage_users'. The
    last-admin safeguards use this so the system is never left with nobody able
    to manage users — covers demote, delete, disable, and self-edit alike."""
    return any(u.has_cap("manage_users")
               for u in User.query.all()
               if u.id != exclude_user_id and u.is_active)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    full_name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128))
    role = db.Column(db.String(48), default="Analyst")   # free-text job title / label; authority comes from capabilities
    password_hash = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    # per-user capability overrides vs the role default; None/{} = pure role
    permissions = db.Column(db.JSON)
    # True right after a manager creates the account with a system temp password;
    # the user is forced to set their own password on first login, then it clears.
    must_change_password = db.Column(db.Boolean, default=False)
    # A manager-requested email change waits here until the account owner
    # confirms it from the CURRENT mailbox (link valid 10 minutes). Nothing on
    # the account changes until then; an unanswered request simply lapses.
    pending_email = db.Column(db.String(128))
    pending_email_by = db.Column(db.Integer)          # manager who asked for it
    pending_email_expires = db.Column(db.DateTime)    # UTC
    # True for a SELF-REGISTERED account that a manager has not approved yet. Such
    # an account is inactive with zero capabilities and cannot sign in until a
    # manager approves it (and assigns its capabilities). Manager-created accounts
    # are never pending.
    pending_approval = db.Column(db.Boolean, default=False)
    # Optional second factor: a knowledge-based security question. When both the
    # question and the (hashed) answer are set, the account is asked the question
    # after the password at sign-in. This is a KNOWLEDGE factor — weaker than a
    # TOTP app or hardware key — but adds a second step beyond the password.
    security_question = db.Column(db.String(200))
    security_answer_hash = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    decisions = db.relationship("Decision", backref="analyst", lazy=True)

    def set_password(self, raw): self.password_hash = generate_password_hash(raw)
    def check_password(self, raw): return check_password_hash(self.password_hash, raw)
    def is_manager(self): return self.has_cap("manage_users")   # "admin" = can manage users (capability, not name)

    @staticmethod
    def _norm_answer(raw):
        """Normalise a security answer so trivial formatting differences don't
        block a correct answer: trim, lowercase, collapse internal whitespace."""
        return " ".join((raw or "").strip().lower().split())

    def set_security_answer(self, raw):
        self.security_answer_hash = generate_password_hash(self._norm_answer(raw))

    def check_security_answer(self, raw):
        if not self.security_answer_hash:
            return False
        return check_password_hash(self.security_answer_hash, self._norm_answer(raw))

    def mfa_enabled(self):
        """True when a security question + answer are set (second factor active)."""
        return bool(self.security_question and self.security_answer_hash)

    @staticmethod
    def email_taken(email, exclude_id=None):
        """True if another account already uses this email. Comparison is
        case-SENSITIVE (Alice@x.com and alice@x.com are treated as different
        addresses). An empty email is never 'taken'."""
        email = (email or "").strip()
        if not email:
            return False
        q = User.query.filter(User.email == email)
        if exclude_id is not None:
            q = q.filter(User.id != exclude_id)
        return db.session.query(q.exists()).scalar()

    def has_cap(self, cap):
        """Effective answer for one capability: an explicit per-user override
        wins, otherwise fall back to the base default. The role name is a label
        and does not affect authority.

        Each capability now gates its OWN page(s): 'view' unlocks the monitoring
        pages, 'approve_events' the Tickets page, 'block_ips' the Firewall Blocks
        page, and so on. There is no implication between them — a user who should
        see the event pages must be granted 'view' explicitly."""
        overrides = self.permissions or {}
        if cap in overrides:
            return bool(overrides[cap])
        return BASE_DEFAULTS.get(cap, False)

    def view_pages(self):
        """The per-read-page visibility map. A stored dict under permissions
        ['view_pages'] wins; when absent, ALL read pages are visible (so existing
        accounts and the first-run admin keep seeing everything)."""
        vp = (self.permissions or {}).get("view_pages")
        if isinstance(vp, dict):
            return {k: bool(vp.get(k, True)) for k in VIEW_PAGE_KEYS}
        return {k: True for k in VIEW_PAGE_KEYS}

    def can_see_page(self, page):
        """True if the user may open one of the 'view' read pages. Requires the
        'view' master AND that this specific page is enabled in view_pages."""
        if not self.has_cap("view"):
            return False
        return self.view_pages().get(page, True)

    def effective_caps(self):
        return {k: self.has_cap(k) for k in CAPABILITY_KEYS}

    def to_dict(self):
        return {
            "id": self.id, "username": self.username, "full_name": self.full_name,
            "email": self.email, "role": self.role, "is_active": self.is_active,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "permissions": self.permissions or {},
            "capabilities": self.effective_caps(),
            "view_pages": self.view_pages(),
            "must_change_password": bool(self.must_change_password),
            "mfa_enabled": self.mfa_enabled(),
            "pending_approval": bool(self.pending_approval),
            # a lapsed request (nobody answered within the time limit) is shown
            # as no request at all; the manager simply sends a new one
            "pending_email": self.pending_email if self.pending_email_live() else None,
            "pending_email_expires": (self.pending_email_expires.isoformat()
                                      if self.pending_email_live() else None),
        }

    def pending_email_live(self):
        """True while a manager's email-change request is still answerable."""
        return bool(self.pending_email and self.pending_email_expires
                    and self.pending_email_expires > datetime.utcnow())


class Event(db.Model):
    """One aggregated event = many raw logs sharing the same source IP + rule."""
    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    dest_ip = db.Column(db.String(45))
    attack_type = db.Column(db.String(64))
    rule = db.Column(db.String(128))
    log_count = db.Column(db.Integer, default=0)

    # Triage output
    confidence = db.Column(db.Float)                 # 0.0 - 1.0
    risk = db.Column(db.String(16))                  # "high" | "uncertain" | "low"
    status = db.Column(db.String(16), default="new") # new|blocked|awaiting|logged|dismissed

    # Investigation output
    mitre_techniques = db.Column(db.JSON)            # ["T1190 ...", ...]
    llm_summary = db.Column(db.JSON)                 # {what_happened, what_could_go_wrong, ...}
    raw_log_sample = db.Column(db.JSON)              # list[str]

    # Enrichment (threat intel / asset / vulnerability)
    threat_intel = db.Column(db.JSON)                # {scope, known_bad, score, ...}
    asset_info = db.Column(db.JSON)                  # {name, criticality, owner, ...}
    vuln_info = db.Column(db.JSON)                   # {exploitable, matching_cves, ...}

    chain_id = db.Column(db.Integer, db.ForeignKey("attack_chains.id"))
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)   # oldest RAW alert/log time
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)    # newest RAW alert/log time
    # When CyREN first ingested/processed this event (its own clock). Distinct
    # from first_seen/last_seen (which are the raw alert times) and, unlike
    # last_seen, never overwritten on re-ingest. Used for end-to-end MTTR:
    # response time (BlockedIP.created_at) - last_seen.
    ingested_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # dismiss with retention (alert suppression): a dismissed event can suppress
    # repeats of the same source+rule until a date, instead of raising a new
    # event/block/email each time. The event is never deleted.
    suppressed_until = db.Column(db.DateTime)      # None = not suppressed
    suppress_reason = db.Column(db.String(200))    # false_positive | benign | ...
    suppress_hits = db.Column(db.Integer, default=0)   # repeats folded in (downgrade counter)
    suppress_notified = db.Column(db.Boolean, default=False)  # expiry asked once
    # false-positive redesign: remember the state a false positive was marked FROM,
    # so Undo restores the ORIGINAL state (blocked / awaiting / logged), not a fixed one.
    fp_prev_status = db.Column(db.String(30))

    # ticketing: open | in_progress | closed, an optional assignee, a close note.
    ticket_status = db.Column(db.String(16), default="open")
    assigned_to = db.Column(db.Integer, db.ForeignKey("users.id"))
    closed_at = db.Column(db.DateTime)
    closed_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    close_note = db.Column(db.String(500))

    def to_dict(self):
        return {
            "id": self.id, "source_ip": self.source_ip, "dest_ip": self.dest_ip,
            "ticket_status": self.ticket_status or "open", "assigned_to": self.assigned_to,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "close_note": self.close_note,
            "attack_type": self.attack_type, "rule": self.rule,
            "log_count": self.log_count, "confidence": self.confidence,
            "risk": self.risk, "status": self.status,
            "mitre_techniques": self.mitre_techniques or [],
            "llm_summary": self.llm_summary or {},
            "raw_log_sample": self.raw_log_sample or [],
            "threat_intel": self.threat_intel or {},
            "asset_info": self.asset_info or {},
            "vuln_info": self.vuln_info or {},
            "chain_id": self.chain_id,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "ingested_at": self.ingested_at.isoformat() if self.ingested_at else None,
            "suppressed_until": self.suppressed_until.isoformat() if self.suppressed_until else None,
            "suppress_reason": self.suppress_reason,
            "suppress_hits": self.suppress_hits or 0,
            "fp_prev_status": self.fp_prev_status,
        }


class AttackChain(db.Model):
    __tablename__ = "attack_chains"

    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(45), index=True)
    highest_risk = db.Column(db.String(16))
    stage_count = db.Column(db.Integer, default=0)
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    # ordered list of {attack_type, mitre, tactic, timestamp}
    stages = db.Column(db.JSON)
    predicted_next = db.Column(db.String(64))

    events = db.relationship("Event", backref="chain", lazy=True)

    def to_dict(self):
        return {
            "id": self.id, "source_ip": self.source_ip,
            "highest_risk": self.highest_risk, "stage_count": self.stage_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "stages": self.stages or [], "predicted_next": self.predicted_next,
        }


class Whitelist(db.Model):
    """Source addresses the analysts trust (scanners, monitoring probes). Their
    events are still detected and recorded, but the Response agent never blocks
    them or sends a high-risk alert, and their events are kept out of the
    training set. Created by db.create_all() on the next start."""
    __tablename__ = "whitelist"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, index=True, nullable=False)
    reason = db.Column(db.String(200), nullable=False)
    added_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {"id": self.id, "ip": self.ip, "reason": self.reason, "added_by": self.added_by,
                "created_at": self.created_at.isoformat() if self.created_at else None}


class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), index=True)
    attack_type = db.Column(db.String(64))
    blocked_by = db.Column(db.String(32))   # "auto" | "analyst"
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    event_id = db.Column(db.Integer, db.ForeignKey("events.id"))

    def to_dict(self):
        return {
            "id": self.id, "ip": self.ip, "attack_type": self.attack_type,
            "blocked_by": self.blocked_by, "active": self.active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "event_id": self.event_id,
        }


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("events.id"))
    title = db.Column(db.String(200))
    risk = db.Column(db.String(16))
    resolution = db.Column(db.String(64))   # auto_blocked|analyst_approved|dismissed
    file_path = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "event_id": self.event_id, "title": self.title,
            "risk": self.risk, "resolution": self.resolution,
            "file_path": self.file_path,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Setting(db.Model):
    """Key-value store for operational settings a manager can change from the UI
    (currently only the auto-block toggle). Distinct from .env deployment config."""
    __tablename__ = "settings"

    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.String(256))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    @staticmethod
    def get(key, default=None):
        row = db.session.get(Setting, key)
        return row.value if row is not None else default

    @staticmethod
    def get_bool(key, default=True):
        v = Setting.get(key)
        return default if v is None else (v == "1")

    @staticmethod
    def set(key, value, user_id=None):
        row = db.session.get(Setting, key)
        if row is None:
            row = Setting(key=key)
            db.session.add(row)
        row.value = None if value is None else str(value)
        row.updated_by = user_id
        return row


class AuditLog(db.Model):
    """Audit trail for sensitive manager actions (e.g. changing the auto-block
    setting). Separate from Decision, which logs per-event analyst decisions."""
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    action = db.Column(db.String(64))
    detail = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "user_id": self.user_id, "action": self.action,
            "detail": self.detail,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ChainPrediction(db.Model):
    """Cached LLM deep-prediction for an attack chain's next step. Generated
    on demand (the "AI deep prediction" button), separate from the fast
    rule-based predicted_next. One latest prediction per chain."""
    __tablename__ = "chain_predictions"

    chain_id = db.Column(db.Integer, db.ForeignKey("attack_chains.id"), primary_key=True)
    prediction = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "chain_id": self.chain_id, "prediction": self.prediction,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Decision(db.Model):
    """An analyst decision. Feeds continuous learning and the profile activity view."""
    __tablename__ = "decisions"

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("events.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    action = db.Column(db.String(32))   # approved|dismissed|reverted
    label = db.Column(db.String(32))    # true_positive|false_positive (training label)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "event_id": self.event_id, "user_id": self.user_id,
            "action": self.action, "label": self.label,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class EventNote(db.Model):
    """An analyst's free-text note/comment on an event (ticket-style). Kept
    separate from Decision (which is a structured triage verdict for training)."""
    __tablename__ = "event_notes"

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("events.id"), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    text = db.Column(db.String(2000))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    edited_at = db.Column(db.DateTime)
    # soft delete: the row stays as a tombstone ("This note was deleted") so the
    # record shows WHO removed a note and WHEN; the text itself is cleared
    deleted_at = db.Column(db.DateTime)
    deleted_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    def to_dict(self):
        return {
            "id": self.id, "event_id": self.event_id, "user_id": self.user_id,
            "text": "" if self.deleted_at else self.text,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "edited_at": self.edited_at.isoformat() if self.edited_at else None,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
            "deleted_by": self.deleted_by,
        }


TICKET_STATUSES = ("queue", "assigned", "in_progress", "closed")
TICKET_CLOSE_REASONS = ("True positive", "False positive", "Duplicate")

ticket_events = db.Table(
    "ticket_events",
    db.Column("ticket_id", db.Integer, db.ForeignKey("tickets.id"), primary_key=True),
    db.Column("event_id", db.Integer, db.ForeignKey("events.id"), primary_key=True),
)


class Ticket(db.Model):
    """A case: one attacker / attack chain worked as a unit. Groups events,
    carries assignment + lifecycle, and is the source of ticket MTTR."""
    __tablename__ = "tickets"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.String(2000))
    source_ip = db.Column(db.String(45), index=True)
    chain_id = db.Column(db.Integer, db.ForeignKey("attack_chains.id"))
    status = db.Column(db.String(16), default="queue")     # queue|assigned|in_progress|closed
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    raised_by = db.Column(db.String(16), default="auto")   # auto | manual
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))  # manual tickets
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    closed_at = db.Column(db.DateTime)
    closed_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    close_reason = db.Column(db.String(32))
    close_note = db.Column(db.String(500))
    # events the analyst deliberately DETACHED — "re-run AI analysis" must not
    # silently re-add them (list of event ids)
    excluded_event_ids = db.Column(db.JSON)

    events = db.relationship("Event", secondary=ticket_events, lazy="subquery")

    def risk(self):
        """Ticket risk = the highest risk among its events (uncertain if none)."""
        r = None
        for e in self.events:
            if e.risk == "high":
                return "high"
            if e.risk == "uncertain":
                r = "uncertain"
            elif r is None and e.risk == "low":
                r = "low"
        return r or "uncertain"

    def to_dict(self, deep=False):
        d = {
            "id": self.id, "title": self.title, "description": self.description,
            "source_ip": self.source_ip, "chain_id": self.chain_id,
            "status": self.status or "queue",
            "assignee_id": self.assignee_id, "raised_by": self.raised_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "close_reason": self.close_reason, "close_note": self.close_note,
            "risk": self.risk(), "event_count": len(self.events),
        }
        if deep:
            d["events"] = [e.to_dict() for e in self.events]
        return d


class TicketComment(db.Model):
    """Discussion thread on a ticket (supports editing and threaded replies)."""
    __tablename__ = "ticket_comments"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("tickets.id"), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    parent_id = db.Column(db.Integer, db.ForeignKey("ticket_comments.id"))  # reply target
    text = db.Column(db.String(2000))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    edited_at = db.Column(db.DateTime)
    # soft delete (tombstone), same as EventNote
    deleted_at = db.Column(db.DateTime)
    deleted_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    def to_dict(self):
        return {
            "id": self.id, "ticket_id": self.ticket_id, "user_id": self.user_id,
            "parent_id": self.parent_id, "text": "" if self.deleted_at else self.text,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "edited_at": self.edited_at.isoformat() if self.edited_at else None,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
            "deleted_by": self.deleted_by,
        }


class TicketActivity(db.Model):
    """Per-ticket audit trail (created / assigned / status / closed / comment)."""
    __tablename__ = "ticket_activity"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("tickets.id"), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))  # None = system
    text = db.Column(db.String(900))   # "Closed — reason\n<note>" keeps the full closing note
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "ticket_id": self.ticket_id, "user_id": self.user_id,
            "text": self.text,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ChatGroup(db.Model):
    """A team chat group (WhatsApp-style). member_ids keeps JOIN ORDER (creator
    first) — admin hand-over goes to the longest-standing member. left_ids are
    ex-members who keep read-only history until they delete the chat."""
    __tablename__ = "chat_groups"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    member_ids = db.Column(db.JSON)          # [user_id, ...] in join order, creator first
    left_ids = db.Column(db.JSON)            # ex-members who still see the history
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {"id": self.id, "name": self.name,
                "member_ids": self.member_ids or [],
                "left_ids": self.left_ids or [],
                "created_by": self.created_by,
                "created_at": self.created_at.isoformat() if self.created_at else None}


class ChatMessage(db.Model):
    """One message: either a DM (peer_id set) or a group post (group_id set).
    May carry an uploaded attachment (file kept under data/uploads/chat)."""
    __tablename__ = "chat_messages"

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    peer_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)    # DM recipient
    group_id = db.Column(db.Integer, db.ForeignKey("chat_groups.id"), index=True)
    text = db.Column(db.String(2000))
    file_name = db.Column(db.String(256))
    file_path = db.Column(db.String(512))
    read = db.Column(db.Boolean, default=False)     # DM read flag (recipient side)
    parent_id = db.Column(db.Integer, db.ForeignKey("chat_messages.id"))  # reply target
    edited_at = db.Column(db.DateTime)
    deleted = db.Column(db.Boolean, default=False)
    pinned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {"id": self.id, "sender_id": self.sender_id, "peer_id": self.peer_id,
                "group_id": self.group_id,
                "text": None if self.deleted else self.text,
                "file_name": None if self.deleted else self.file_name,
                "file_path": None if self.deleted else self.file_path,
                "read": bool(self.read), "parent_id": self.parent_id,
                "edited_at": self.edited_at.isoformat() if self.edited_at else None,
                "deleted": bool(self.deleted), "pinned": bool(self.pinned),
                "created_at": self.created_at.isoformat() if self.created_at else None}


class ChatGroupSeen(db.Model):
    """Per-member group read marker: the last message id this user has seen.
    (DMs use ChatMessage.read; groups need one marker per member instead.)"""
    __tablename__ = "chat_group_seen"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    group_id = db.Column(db.Integer, db.ForeignKey("chat_groups.id"), index=True)
    last_read_id = db.Column(db.Integer, default=0)

    __table_args__ = (db.UniqueConstraint("user_id", "group_id", name="uq_group_seen"),)


class ReportNote(db.Model):
    """A summary an analyst typed for a SOC Activity Report. Kept with author
    and time so it can be shown again in later reports; never edited in place.
    Created by db.create_all() on the next start."""
    __tablename__ = "report_notes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    text = db.Column(db.String(4000), nullable=False)
    period_label = db.Column(db.String(80))
    image_path = db.Column(db.String(300))          # optional PNG/JPG attachment
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    edited_at = db.Column(db.DateTime)               # shown as "(edited)", like a ticket comment
    deleted_at = db.Column(db.DateTime)              # tombstone, text is kept out of view
    deleted_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    def to_dict(self):
        return {"id": self.id, "user_id": self.user_id, "text": self.text,
                "period": self.period_label, "has_image": bool(self.image_path),
                "created_at": self.created_at.isoformat() if self.created_at else None,
                "edited": bool(self.edited_at), "deleted": bool(self.deleted_at)}


class Notification(db.Model):
    """In-app notification (bell): ticket assigned to you, @mention, etc."""
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    kind = db.Column(db.String(24))          # ticket_assigned | mention | ...
    ref_id = db.Column(db.Integer)           # e.g. ticket id
    text = db.Column(db.String(300))
    read = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "kind": self.kind, "ref_id": self.ref_id,
            "text": self.text, "read": bool(self.read),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
