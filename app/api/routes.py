"""
REST API for the CyREN dashboard.

These endpoints replace the mock data in the frontend. Each maps to an
interface described in Chapter 3.

    GET  /api/dashboard              -> Dashboard summary
    GET  /api/events                 -> All Events (filterable)
    GET  /api/events/<id>            -> Event Detail
    POST /api/events/<id>/decision   -> approve / dismiss (Human Approval)
    GET  /api/chains                 -> Attack Chain list
    GET  /api/chains/<id>            -> one chain
    GET  /api/blocked                -> Firewall Blocks
    POST /api/blocked/<id>/unblock   -> unblock an IP
    GET  /api/reports                -> Incident Reports
    GET  /api/users                  -> User Management (manager only)
    POST /api/ingest                 -> run one event through the pipeline
"""
import os
import re
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, send_file
from flask_login import login_required, current_user

from app.models.db import db, Event, AttackChain, BlockedIP, Report, User, Decision
from app.agents.pipeline import run_pipeline

api = Blueprint("api", __name__, url_prefix="/api")

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _parse_date_range():
    """Read optional ?from=YYYY-MM-DD&to=YYYY-MM-DD query params.

    Returns (start, end, error). `end` is exclusive (start of the next day)
    so a single-day range covers the whole day.
    """
    f = request.args.get("from")
    t = request.args.get("to")
    start = end = None
    try:
        if f:
            start = datetime.strptime(f, "%Y-%m-%d")
        if t:
            end = datetime.strptime(t, "%Y-%m-%d") + timedelta(days=1)
    except ValueError:
        return None, None, "invalid date, expected YYYY-MM-DD"
    if start and end and start >= end:
        return None, None, "'from' date must not be after 'to' date"
    return start, end, None


def _apply_date_range(query, start, end):
    if start:
        query = query.filter(Event.last_seen >= start)
    if end:
        query = query.filter(Event.last_seen < end)
    return query


# ------------------------------------------------------------------ dashboard
@api.get("/dashboard")
@login_required
def dashboard():
    start, end, err = _parse_date_range()
    if err:
        return jsonify({"error": err}), 400
    events = _apply_date_range(Event.query, start, end).all()
    awaiting = [e for e in events if e.status == "awaiting"]
    blocked = BlockedIP.query.filter_by(active=True).count()
    low = [e for e in events if e.risk == "low"]

    # attack-type distribution for the doughnut
    dist = {}
    for e in events:
        dist[e.attack_type] = dist.get(e.attack_type, 0) + 1

    return jsonify({
        "raw_log_total": sum(e.log_count for e in events),
        "event_total": len(events),
        "awaiting": [e.to_dict() for e in awaiting],
        "blocked_count": blocked,
        "low_count": len(low),
        "attack_type_distribution": dist,
    })


# --------------------------------------------------------------------- events
@api.get("/events")
@login_required
def list_events():
    start, end, err = _parse_date_range()
    if err:
        return jsonify({"error": err}), 400
    q = _apply_date_range(Event.query, start, end)
    risk = request.args.get("risk")
    status = request.args.get("status")
    ip = request.args.get("ip")
    if risk:   q = q.filter_by(risk=risk)
    if status: q = q.filter_by(status=status)
    if ip:     q = q.filter(Event.source_ip.contains(ip))
    return jsonify([e.to_dict() for e in q.order_by(Event.last_seen.desc()).all()])


@api.get("/events/<int:event_id>")
@login_required
def event_detail(event_id):
    e = Event.query.get_or_404(event_id)
    return jsonify(e.to_dict())


@api.post("/events/<int:event_id>/decision")
@login_required
def decide(event_id):
    e = Event.query.get_or_404(event_id)
    data = request.get_json(force=True)
    action = data.get("action")   # "approved" | "dismissed"

    if action == "approved":
        from app.agents.response import response_agent
        response_agent.block_ip(e.source_ip)
        e.status = "blocked"
        db.session.add(BlockedIP(ip=e.source_ip, attack_type=e.attack_type,
                                 blocked_by="analyst", event_id=e.id))
        label = "true_positive"
    elif action == "dismissed":
        e.status = "dismissed"
        label = "false_positive"
    else:
        return jsonify({"error": "invalid action"}), 400

    db.session.add(Decision(event_id=e.id, user_id=current_user.id,
                            action=action, label=label))
    db.session.commit()
    return jsonify({"ok": True, "event": e.to_dict()})


# --------------------------------------------------------------------- chains
@api.get("/chains")
@login_required
def list_chains():
    return jsonify([c.to_dict() for c in AttackChain.query.all()])


@api.get("/chains/<int:chain_id>")
@login_required
def chain_detail(chain_id):
    return jsonify(AttackChain.query.get_or_404(chain_id).to_dict())


# -------------------------------------------------------------------- blocked
@api.get("/blocked")
@login_required
def list_blocked():
    return jsonify([b.to_dict() for b in BlockedIP.query.order_by(BlockedIP.created_at.desc()).all()])


@api.post("/blocked")
@login_required
def add_block():
    """Manually block an IP (the "Add Block" button on Firewall Blocks)."""
    data = request.get_json(force=True)
    ip = (data.get("ip") or "").strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) or any(int(o) > 255 for o in ip.split(".")):
        return jsonify({"error": "invalid IPv4 address"}), 400
    if BlockedIP.query.filter_by(ip=ip, active=True).first():
        return jsonify({"error": "IP is already blocked"}), 409
    from app.agents.response import response_agent
    response_agent.block_ip(ip)
    b = BlockedIP(ip=ip, attack_type=data.get("reason") or "Manual block",
                  blocked_by="analyst")
    db.session.add(b)
    db.session.commit()
    return jsonify({"ok": True, "block": b.to_dict()}), 201


@api.post("/blocked/<int:block_id>/unblock")
@login_required
def unblock(block_id):
    from app.agents.response import response_agent
    b = BlockedIP.query.get_or_404(block_id)
    removed = response_agent.unblock_ip(b.ip)
    b.active = False
    db.session.commit()
    return jsonify({"ok": True, "iptables_removed": removed})


# -------------------------------------------------------------------- reports
@api.get("/reports")
@login_required
def list_reports():
    return jsonify([r.to_dict() for r in Report.query.order_by(Report.created_at.desc()).all()])


def _report_path(report):
    """Resolve the stored (possibly relative) report path; None if missing."""
    path = report.file_path or ""
    if not path:
        return None
    if not os.path.isabs(path):
        path = os.path.join(_PROJECT_ROOT, path)
    return path if os.path.isfile(path) else None


@api.get("/reports/<int:report_id>/download")
@login_required
def download_report(report_id):
    r = Report.query.get_or_404(report_id)
    path = _report_path(r)
    if not path:
        return jsonify({"error": "report file not found on disk"}), 404
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@api.get("/reports/<int:report_id>/preview")
@login_required
def preview_report(report_id):
    r = Report.query.get_or_404(report_id)
    path = _report_path(r)
    if not path:
        return jsonify({"error": "report file not found on disk"}), 404
    return send_file(path)   # inline: the browser renders the PDF itself


# ---------------------------------------------------------------------- users
@api.get("/users")
@login_required
def list_users():
    if not current_user.is_manager():
        return jsonify({"error": "manager only"}), 403
    return jsonify([u.to_dict() for u in User.query.all()])


@api.post("/users")
@login_required
def create_user():
    """Manager-only Add User (same validation as self-registration)."""
    if not current_user.is_manager():
        return jsonify({"error": "manager only"}), 403
    from app.api.auth import _password_ok, PASSWORD_RULE
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    full_name = (data.get("full_name") or "").strip()
    password = data.get("password") or ""
    role = data.get("role") or "analyst"
    if not username or not full_name or not password:
        return jsonify({"error": "username, full name and password are required"}), 400
    if role not in ("analyst", "manager"):
        return jsonify({"error": "invalid role"}), 400
    if not _password_ok(password):
        return jsonify({"error": PASSWORD_RULE}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "username already taken"}), 409
    u = User(username=username, full_name=full_name,
             email=(data.get("email") or "").strip(), role=role)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    return jsonify({"ok": True, "user": u.to_dict()}), 201


@api.patch("/users/<int:user_id>")
@login_required
def update_user(user_id):
    """Manager-only edit: full name, role, enable/disable."""
    if not current_user.is_manager():
        return jsonify({"error": "manager only"}), 403
    u = User.query.get_or_404(user_id)
    data = request.get_json(force=True)
    if "full_name" in data:
        name = (data.get("full_name") or "").strip()
        if not name:
            return jsonify({"error": "full name cannot be empty"}), 400
        u.full_name = name
    if "role" in data:
        if data["role"] not in ("analyst", "manager"):
            return jsonify({"error": "invalid role"}), 400
        u.role = data["role"]
    if "is_active" in data:
        if u.id == current_user.id and not data["is_active"]:
            return jsonify({"error": "you cannot disable your own account"}), 400
        u.is_active = bool(data["is_active"])
    db.session.commit()
    return jsonify({"ok": True, "user": u.to_dict()})


# ------------------------------------------------------------------- activity
@api.get("/me/activity")
@login_required
def my_activity():
    """Decision history of the signed-in analyst (My Profile page)."""
    decisions = (Decision.query.filter_by(user_id=current_user.id)
                 .order_by(Decision.created_at.desc()).all())
    counts = {"approved": 0, "dismissed": 0, "reverted": 0}
    for d in decisions:
        counts[d.action] = counts.get(d.action, 0) + 1
    recent = []
    for d in decisions[:8]:
        e = Event.query.get(d.event_id) if d.event_id else None
        item = d.to_dict()
        item["source_ip"] = e.source_ip if e else None
        item["attack_type"] = e.attack_type if e else None
        recent.append(item)
    return jsonify({"counts": counts, "recent": recent})


# ---------------------------------------------------------------- enrichment
@api.get("/assets")
@login_required
def list_assets():
    from app.enrichment.asset_assessment import Asset
    return jsonify([a.to_dict() for a in Asset.query.all()])


@api.get("/vulnerabilities")
@login_required
def list_vulnerabilities():
    from app.enrichment.vuln_assessment import Vulnerability
    ip = request.args.get("ip")
    q = Vulnerability.query
    if ip:
        q = q.filter_by(ip=ip)
    return jsonify([v.to_dict() for v in q.all()])


@api.get("/threat-intel/<ip>")
@login_required
def threat_lookup(ip):
    from app.enrichment.threat_intel import threat_intel
    return jsonify(threat_intel.lookup(ip))


# --------------------------------------------------------------------- ingest
@api.post("/ingest")
@login_required
def ingest():
    """
    Run one event through the multi-agent pipeline and persist the result.
    Body: {source_ip, dest_ip, rule, log_count, raw_logs}
    In production this is driven by siem_service, not called by hand.
    """
    from app.services.event_service import persist_pipeline_result
    event = request.get_json(force=True)
    state = run_pipeline(event)
    e = persist_pipeline_result(state)
    return jsonify({"ok": True, "event": e.to_dict()})
