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


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    full_name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128))
    role = db.Column(db.String(32), default="analyst")   # "analyst" | "manager"
    password_hash = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    decisions = db.relationship("Decision", backref="analyst", lazy=True)

    def set_password(self, raw): self.password_hash = generate_password_hash(raw)
    def check_password(self, raw): return check_password_hash(self.password_hash, raw)
    def is_manager(self): return self.role == "manager"

    def to_dict(self):
        return {
            "id": self.id, "username": self.username, "full_name": self.full_name,
            "email": self.email, "role": self.role, "is_active": self.is_active,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }


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

    def to_dict(self):
        return {
            "id": self.id, "source_ip": self.source_ip, "dest_ip": self.dest_ip,
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
