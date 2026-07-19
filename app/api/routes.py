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
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

from app.models.db import db, Event, AttackChain, BlockedIP, Report, User, Decision
from app.agents.pipeline import run_pipeline

api = Blueprint("api", __name__, url_prefix="/api")


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


# ---------------------------------------------------------------------- users
@api.get("/users")
@login_required
def list_users():
    if not current_user.is_manager():
        return jsonify({"error": "manager only"}), 403
    return jsonify([u.to_dict() for u in User.query.all()])


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
