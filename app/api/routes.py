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
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, jsonify, send_file
from flask_login import login_required, current_user

from sqlalchemy import func, or_
from app.models.db import (db, Event, AttackChain, BlockedIP, Report, User, ReportNote,
                           Decision, Setting, AuditLog, ChainPrediction, EventNote, Whitelist,
                           Ticket, TicketComment, TicketActivity, Notification,
                           ChatGroup, ChatMessage, ChatGroupSeen,
                           TICKET_STATUSES, TICKET_CLOSE_REASONS,
                           CAPABILITIES, CAPABILITY_KEYS, ROLE_DEFAULTS,
                           BASE_DEFAULTS, has_other_admin,
                           VIEW_PAGES, VIEW_PAGE_KEYS, DEFAULT_VIEW_PAGES,
                           DEFAULT_NEW_CAPS)
from app.agents.pipeline import run_pipeline

api = Blueprint("api", __name__, url_prefix="/api")

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _require_cap(cap):
    """Guard helper. Returns a 403 (error_response, status) tuple if the signed-in
    user lacks the capability, or None if they have it. Usage:

        deny = _require_cap("manage_assets")
        if deny:
            return deny
    """
    if not current_user.has_cap(cap):
        return jsonify({"error": "You don't have permission to do that."}), 403
    return None


# ---------------------------------------------------------------------------
# Page-level access control (server side).
#
# The UI hides pages a user may not see, but the server must ALSO refuse the
# data behind them, otherwise the permission is only cosmetic (a stripped user
# could still pull the data by calling the API directly). Each capability gates
# its OWN page(s):
#   view           -> the read/monitoring endpoints below. Which individual read
#                     PAGES a user sees is further toggled per user (view_pages);
#                     that is a nav concern handled in the UI, except Audit Logs,
#                     which is enforced here (off by default, must be granted).
#   approve_events -> the Tickets page (detail/report) and every ticket action.
#   block_ips      -> the Firewall Blocks page + block/unblock actions.
# Cross-page data endpoints are widened so a viewer is not 403'd mid-page: the
# ticket LIST also feeds the Reports report-builder, so a plain viewer may read
# it; the block LIST enriches an event's detail, but that call already degrades
# gracefully, so it stays strict (block_ips).
# Action endpoints (block/unblock, approve/dismiss, false-positive) also keep
# their own inline _require_cap guards; the map below is the single gate for the
# read endpoints and the ticket actions that have no inline guard.
# ---------------------------------------------------------------------------
def _deny():
    return jsonify({"error": "You don't have permission to do that."}), 403

# read/monitoring endpoints — require the 'view' master
_VIEW_READ = {"api." + _n for _n in (
    "dashboard", "list_events", "event_detail", "event_timeline",
    "list_chains", "chain_detail", "get_chain_prediction", "download_chain_report",
    "list_reports", "download_event_report", "preview_event_report",
    "download_report", "preview_report", "events_report_zip", "reports_zip",
    "raw_logs", "raw_logs_export",
)}
# Audit Logs — require 'view' AND the (off-by-default) audit read page
_AUDIT_READ = {"api.get_audit"}
# Tickets — page detail/report and every ticket action need approve_events
_TICKET_CAP = {"api." + _n for _n in (
    "case_detail", "case_report", "create_case", "update_case", "delete_case",
    "add_case_comment", "edit_case_comment", "delete_case_comment",
    "case_analyze", "cases_auto_raise", "attach_case_events", "detach_case_event",
)}
# Ticket LISTS stay readable by a plain viewer (Reports report-builder lists
# tickets) as well as by anyone who can work tickets.
_TICKET_LIST = {"api.list_cases", "api.list_tickets"}
# Firewall Blocks list — require block_ips (block/unblock actions guard inline)
_BLOCK_READ = {"api.list_blocked"}


@api.before_request
def _enforce_page_gates():
    """Central page-level authorization. Runs before every blueprint view; an
    unauthenticated request falls through to each view's @login_required."""
    ep = request.endpoint
    if not ep or not current_user.is_authenticated:
        return
    if ep in _VIEW_READ and not current_user.has_cap("view"):
        return _deny()
    if ep in _AUDIT_READ and not current_user.can_see_page("audit"):
        return _deny()
    if ep in _TICKET_CAP and not current_user.has_cap("approve_events"):
        return _deny()
    if ep in _TICKET_LIST and not (current_user.has_cap("view")
                                   or current_user.has_cap("approve_events")):
        return _deny()
    if ep in _BLOCK_READ and not current_user.has_cap("block_ips"):
        return _deny()


@api.get("/capabilities")
@login_required
def list_capabilities():
    """Capability catalogue for the UI: the friendly labels, the per-role
    defaults, and the current user's own effective capabilities. Any signed-in
    user may read this (the UI uses it to show/hide controls)."""
    return jsonify({
        "capabilities": CAPABILITIES,
        "view_pages": VIEW_PAGES,              # the read-page sub-toggles under 'view'
        "default_caps": DEFAULT_NEW_CAPS,      # capabilities pre-ticked for a new account
        "default_view_pages": DEFAULT_VIEW_PAGES,   # read pages pre-ticked for a new account
        "base_defaults": BASE_DEFAULTS,        # fallback baseline (existing partial accounts)
        "role_defaults": ROLE_DEFAULTS,        # kept for backward compatibility
        "me": current_user.effective_caps(),
        "my_pages": current_user.view_pages(),      # this user's own per-read-page visibility
    })


def _reachable(url, timeout=1.5, headers=None):
    """True if the URL responds at all (any HTTP status counts as 'up'); False on
    a connection error or timeout. Real check, no fabricated status."""
    import urllib.request
    import urllib.error
    try:
        req = urllib.request.Request(url, headers=headers or {})
        urllib.request.urlopen(req, timeout=timeout).close()
        return True
    except urllib.error.HTTPError:
        return True                 # the server answered (even with 4xx/5xx) -> it's up
    except Exception:
        return False


@api.get("/integrations")
@login_required
def integrations_health():
    """LIVE health of the external services CyREN depends on. Each row is a real
    check with a short timeout -- up / down / not configured -- so the Settings
    page shows the true state instead of a static 'not monitored' label."""
    from config.settings import settings as cfg
    rows = []

    es = cfg.ELASTICSEARCH_URL
    rows.append({"name": "Elasticsearch (SIEM)", "config": "ELASTICSEARCH_URL",
                 "target": es, "status": "up" if _reachable(es) else "down"})

    if cfg.LLM_PROVIDER == "ollama":
        ok = _reachable(cfg.OLLAMA_HOST.rstrip("/") + "/api/tags")
        rows.append({"name": "Ollama LLM", "config": "OLLAMA_HOST", "model": cfg.OLLAMA_MODEL,
                     "target": cfg.OLLAMA_HOST, "status": "up" if ok else "down"})
    else:
        if cfg.GROQ_API_KEY:
            ok = _reachable("https://api.groq.com/openai/v1/models", timeout=2.5,
                            headers={"Authorization": f"Bearer {cfg.GROQ_API_KEY}"})
            status = "up" if ok else "down"
        else:
            status = "not configured"
        rows.append({"name": "Groq LLM", "config": "GROQ_API_KEY", "model": cfg.GROQ_MODEL,
                     "target": "api.groq.com", "status": status})

    chroma = cfg.CHROMA_PERSIST_DIR
    chroma_abs = chroma if os.path.isabs(chroma) else os.path.join(_PROJECT_ROOT, chroma)
    if os.path.isdir(chroma_abs) and os.listdir(chroma_abs):
        cstatus = "ready"
    elif os.path.isdir(chroma_abs):
        cstatus = "empty"
    else:
        cstatus = "missing"
    rows.append({"name": "ChromaDB", "config": "CHROMA_PERSIST_DIR",
                 "target": chroma, "status": cstatus})

    # only the service name and its state leave the server: the host addresses,
    # ports, directory paths and model names stay internal (the page never
    # showed them, and a signed-in account should not be able to map the
    # back-end from this endpoint)
    public = [{"name": r["name"], "status": r["status"]} for r in rows]
    return jsonify({"integrations": public})


def _parse_bound(value, is_end):
    """Parse a date or date-time bound.

    Accepts 'YYYY-MM-DD' (whole day; an end bound rolls to the next midnight
    so the day is included) and 'YYYY-MM-DD HH:MM' / 'YYYY-MM-DDTHH:MM'
    (exact minute, with an end bound rolling to the end of that minute).
    """
    v = value.strip().replace("T", " ")
    for fmt, is_day in (("%Y-%m-%d %H:%M:%S", False), ("%Y-%m-%d %H:%M", False),
                        ("%Y-%m-%d", True)):
        try:
            dt = datetime.strptime(v, fmt)
        except ValueError:
            continue
        if is_end:
            dt += timedelta(days=1) if is_day else timedelta(minutes=1)
        return dt
    raise ValueError(value)


def _parse_date_range():
    """Read optional ?from=&to= query params (date or date-time).

    Returns (start, end, error); `end` is exclusive.
    """
    f = request.args.get("from")
    t = request.args.get("to")
    start = end = None
    try:
        if f:
            start = _parse_bound(f, is_end=False)
        if t:
            end = _parse_bound(t, is_end=True)
    except ValueError:
        return None, None, "invalid date, expected YYYY-MM-DD or YYYY-MM-DD HH:MM"
    if start and end and start >= end:
        return None, None, "'from' must not be after 'to'"
    return start, end, None


def _apply_date_range(query, start, end):
    """Keep events whose activity window overlaps [start, end).

    An event spans first_seen..last_seen, so matching on overlap means a
    search for the time shown in the table finds that event, whether the
    user searched by its start or its end.
    """
    first = db.func.coalesce(Event.first_seen, Event.last_seen)
    last = db.func.coalesce(Event.last_seen, Event.first_seen)
    if start:
        query = query.filter(last >= start)
    if end:
        query = query.filter(first < end)
    return query


def _apply_created_range(query, col, start, end):
    """Filter a query by a single timestamp column within [start, end). Used to
    scope audit / firewall rows to the export's chosen date range."""
    if start:
        query = query.filter(col >= start)
    if end:
        query = query.filter(col < end)
    return query


# ------------------------------------------------------------------ dashboard
@api.get("/dashboard")
@login_required
def dashboard():
    start, end, err = _parse_date_range()
    if err:
        return jsonify({"error": err}), 400
    # Aggregate with SQL COUNT / GROUP BY instead of loading every event row into
    # memory — same numbers, but it no longer hydrates thousands of ORM objects
    # (the main reason the overview was slow on a large database). Only the
    # (usually few) 'awaiting' events are hydrated, for the Action Required panel.
    base = _apply_date_range(Event.query, start, end)
    event_total = base.count()
    low_count = base.filter(Event.risk == "low").count()
    awaiting = base.filter(Event.status == "awaiting").all()
    # scope blocks + open tickets to the selected window too, so the WHOLE
    # overview reflects the chosen period — not just the events table. With no
    # date filter, keep the live "currently blocked / currently open" counts.
    if start or end:
        blocked = _apply_created_range(BlockedIP.query, BlockedIP.created_at, start, end).count()
        open_tickets = _apply_created_range(
            Ticket.query.filter(Ticket.status != "closed"), Ticket.created_at, start, end).count()
    else:
        blocked = BlockedIP.query.filter_by(active=True).count()
        open_tickets = Ticket.query.filter(Ticket.status != "closed").count()
    _bset = _blocked_ip_set()

    # attack-type distribution for the doughnut — GROUP BY, not a Python loop
    dist = {name: n for name, n in _apply_date_range(
        db.session.query(Event.attack_type, db.func.count(Event.id)), start, end
    ).group_by(Event.attack_type).all()}

    # "logs collected" = the real Filebeat/Elasticsearch document total for the
    # same window (the true volume of telemetry ingested); fall back to the
    # aggregated event log-line sum (also via SQL) if Elasticsearch is unavailable.
    from app.services.siem_service import siem_service
    raw_total = siem_service.count_logs(start, end)
    if raw_total is None:
        raw_total = base.with_entities(
            db.func.coalesce(db.func.sum(Event.log_count), 0)).scalar() or 0

    return jsonify({
        "raw_log_total": raw_total,
        "event_total": event_total,
        "awaiting": [{**e.to_dict(), "source_blocked": e.source_ip in _bset} for e in awaiting],
        # global count of everything still awaiting a decision, independent of the
        # date filter, so the sidebar badge always matches the Approvals table.
        "pending_total": Event.query.filter_by(status="awaiting").count(),
        "blocked_count": blocked,
        "open_ticket_total": open_tickets,
        "low_count": low_count,
        "attack_type_distribution": dist,
    })


# --------------------------------------------------------------------- search
@api.get("/search")
@login_required
def global_search():
    """Cross-system search across events, attack chains, blocked IPs, reports
    and (managers only) users. Returns grouped results the UI renders as a
    jump-to dropdown, so the top-bar search finds anything in the system."""
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"events": [], "chains": [], "blocked": [], "reports": [], "users": []})
    like = f"%{q}%"
    LIM = 6

    ev_conds = [Event.source_ip.ilike(like), Event.attack_type.ilike(like),
                Event.rule.ilike(like), Event.status.ilike(like), Event.risk.ilike(like)]
    if q.isdigit():
        ev_conds.append(Event.id == int(q))
    events = (Event.query.filter(Event.status != "dismissed")
              .filter(db.or_(*ev_conds))
              .order_by(Event.last_seen.desc()).limit(LIM).all())

    chains = (AttackChain.query.filter(AttackChain.source_ip.ilike(like))
              .order_by(AttackChain.id.desc()).limit(LIM).all())

    blocked = (BlockedIP.query.filter(BlockedIP.active.is_(True))
               .filter(db.or_(BlockedIP.ip.ilike(like), BlockedIP.attack_type.ilike(like)))
               .order_by(BlockedIP.created_at.desc()).limit(LIM).all())

    reports = (Report.query
               .filter(db.or_(Report.title.ilike(like), Report.resolution.ilike(like)))
               .order_by(Report.id.desc()).limit(LIM).all())

    # user accounts are intentionally NOT surfaced in the global search
    users = []

    def _title(s): return (s or "").replace("_", " ").title()
    return jsonify({
        "events": [{"id": e.id,
                    "label": f"#{e.id} {e.attack_type or 'Event'} from {e.source_ip}",
                    "sub": f"{_title(e.risk)} · {_title(e.status)}"} for e in events],
        "chains": [{"id": c.id, "label": f"Chain from {c.source_ip}",
                    "sub": f"{c.stage_count or 0} stages · {_title(c.highest_risk)}"} for c in chains],
        "blocked": [{"id": b.id, "ip": b.ip, "label": b.ip,
                     "sub": f"{b.attack_type or 'blocked'} · {b.blocked_by or ''}"} for b in blocked],
        "reports": [{"id": r.id, "label": r.title or f"Report #{r.id}",
                     "sub": _title(r.risk)} for r in reports],
        "users": [{"id": u.id, "label": f"{u.full_name} ({u.username})",
                   "sub": u.role or "User"} for u in users],
    })


# ------------------------------------------------------------------- activity
@api.get("/activity")
@login_required
def activity_feed():
    """Unified reverse-chronological feed of what the system actually did:
    events triaged (ingested_at), IPs blocked, analyst decisions, and audited
    settings changes. Every entry comes from a real record - nothing synthetic."""
    limit = min(int(request.args.get("limit", 40) or 40), 500)
    items = []

    for e in Event.query.order_by(Event.ingested_at.desc()).limit(limit).all():
        conf = f" ({e.confidence * 100:.0f}%)" if e.confidence is not None else ""
        items.append({
            "ts": e.ingested_at.isoformat() if e.ingested_at else None,
            "kind": "triage", "icon": "cpu",
            "text": f"Triaged {e.attack_type or 'event'} from {e.source_ip} "
                    f"-> {(e.risk or 'n/a').upper()}{conf}",
            "event_id": e.id,
        })

    for b in BlockedIP.query.order_by(BlockedIP.created_at.desc()).limit(limit).all():
        items.append({
            "ts": b.created_at.isoformat() if b.created_at else None,
            "kind": "block", "icon": "shield-lock",
            "text": f"Blocked {b.ip}" + (f" - {b.attack_type}" if b.attack_type else "")
                    + f" ({b.blocked_by or 'manual'})",
            "ip": b.ip,
        })

    users = {u.id: u.username for u in User.query.all()}
    for d in Decision.query.order_by(Decision.created_at.desc()).limit(limit).all():
        items.append({
            "ts": d.created_at.isoformat() if d.created_at else None,
            "kind": "decision", "icon": "person-check",
            "text": f"{users.get(d.user_id, 'analyst')} {d.action} event #{d.event_id}",
            "event_id": d.event_id,
        })

    for a in AuditLog.query.order_by(AuditLog.created_at.desc()).limit(limit).all():
        items.append({
            "ts": a.created_at.isoformat() if a.created_at else None,
            "kind": "audit", "icon": "sliders",
            "text": a.detail or a.action,
        })

    items = [x for x in items if x["ts"]]
    items.sort(key=lambda x: x["ts"], reverse=True)
    return jsonify({
        "items": items[:limit],
        "processed_total": Event.query.count(),
        "blocked_active": BlockedIP.query.filter_by(active=True).count(),
    })


# ----------------------------------------------------------------------- chat
@api.post("/chat")
@login_required
def chat():
    """SOC assistant: answer a natural-language question grounded in real CyREN
    data (events, chains, blocked IPs) via the local LLM, with multi-turn context."""
    data = request.get_json(force=True)
    q = (data.get("question") or "").strip()
    if not q:
        return jsonify({"ok": False, "error": "empty question"}), 400
    if len(q) > 500:
        q = q[:500]
    history = data.get("history")
    if not isinstance(history, list):
        history = []
    from app.services.chat_service import answer_question
    return jsonify(answer_question(q, history))


@api.get("/events/<int:event_id>/timeline")
@login_required
def event_timeline(event_id):
    """Real per-event processing timeline: the stages the 4-agent pipeline
    actually took for this event, with real timestamps. Drives the AI Assistant's
    right-hand investigation panel."""
    e = db.session.get(Event, event_id)
    if e is None:
        return jsonify({"error": "not found"}), 404
    iso = lambda dt: dt.isoformat() if dt else None
    conf = round((e.confidence or 0) * 100)
    steps = [
        {"stage": "Detection", "icon": "bi-broadcast", "time": iso(e.first_seen),
         "title": "Alert detected",
         "detail": f"{e.attack_type or 'Activity'} from {e.source_ip}; "
                   f"{e.log_count or 0} log line(s)."},
        {"stage": "Triage (XGBoost)", "icon": "bi-cpu", "time": iso(e.ingested_at),
         "title": f"Risk tier: {(e.risk or 'n/a').upper()}",
         "detail": f"XGBoost confidence {conf}%; rule: {e.rule or 'n/a'}."},
    ]
    if (e.mitre_techniques or (e.llm_summary or {}).get("what_happened")):
        wh = (e.llm_summary or {}).get("what_happened") or ""
        steps.append({"stage": "Investigation (MITRE + LLM)", "icon": "bi-search",
                      "time": iso(e.ingested_at), "title": "Techniques retrieved and analysed",
                      "detail": ("MITRE: " + (", ".join(e.mitre_techniques or []) or "n/a"))
                                + (f" — {wh}" if wh else "")})
    if e.chain_id:
        ch = db.session.get(AttackChain, e.chain_id)
        if ch:
            steps.append({"stage": "Correlation (kill chain)", "icon": "bi-diagram-3",
                          "time": iso(ch.last_seen),
                          "title": f"Part of a {ch.stage_count}-stage attack chain",
                          "detail": f"Highest risk {ch.highest_risk}; chain #{ch.id}."})
    blk = (BlockedIP.query.filter_by(event_id=e.id).first()
           or BlockedIP.query.filter_by(ip=e.source_ip, active=True).first())
    if e.status == "blocked" or (blk and blk.active):
        steps.append({"stage": "Response", "icon": "bi-shield-lock",
                      "time": iso(blk.created_at) if blk else None,
                      "title": "Source blocked at the firewall",
                      "detail": f"iptables/ipset DROP ({blk.blocked_by if blk else 'auto'})."})
    elif e.status == "awaiting":
        steps.append({"stage": "Response", "icon": "bi-hourglass-split", "time": None,
                      "title": "Awaiting human approval",
                      "detail": "Routed to the Human Approval queue; no block applied yet."})
    else:
        steps.append({"stage": "Response", "icon": "bi-journal-text", "time": None,
                      "title": "Logged", "detail": "Low risk; logged only, no action taken."})
    return jsonify({"event_id": e.id, "source_ip": e.source_ip,
                    "attack_type": e.attack_type, "risk": e.risk,
                    "status": e.status, "steps": steps})


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
    # LIGHT mode (used by the dashboard): return only the few columns the overview
    # actually needs, skipping the heavy per-event JSON (llm_summary, raw log
    # sample, threat-intel, asset/vuln info) and the blocked-set / ticket joins.
    # This keeps the same rows but a tiny fraction of the payload.
    if request.args.get("light"):
        rows = q.order_by(Event.last_seen.desc()).with_entities(
            Event.id, Event.source_ip, Event.attack_type, Event.risk, Event.status,
            Event.log_count, Event.chain_id, Event.first_seen, Event.last_seen,
            Event.confidence).all()
        return jsonify([{
            "id": r.id, "source_ip": r.source_ip, "attack_type": r.attack_type,
            "risk": r.risk, "status": r.status, "log_count": r.log_count,
            "chain_id": r.chain_id, "confidence": r.confidence,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        } for r in rows])
    blocked = _blocked_ip_set()   # live 'source blocked' flag, separate from status
    # which ticket each event belongs to (case model)
    tk_map = {r[0]: r[1] for r in
              db.session.execute(db.text("SELECT event_id, ticket_id FROM ticket_events")).fetchall()}
    # fallback: an event with no ticket of its own but whose attack chain has a
    # ticket is shown under that ticket, so All Events matches the Event Detail page
    chain_tk = {t.chain_id: t.id for t in
                Ticket.query.filter(Ticket.chain_id.isnot(None)).all()}
    out = []
    for e in q.order_by(Event.last_seen.desc()).all():
        d = e.to_dict()
        d["source_blocked"] = e.source_ip in blocked
        d["ticket_id"] = tk_map.get(e.id) or (chain_tk.get(e.chain_id) if e.chain_id else None)
        out.append(d)
    return jsonify(out)


def _response_log(ip):
    """Block/unblock/reblock audit trail for a source IP: who, when, why."""
    if not ip:
        return []
    # _audit_block writes the IP quoted: "'192.168.0.5' - reason: …" (or just
    # "'192.168.0.5'"). Match that exact shape — the old `ip + " %"` pattern
    # never matched, so the response history + PDF response log were always empty.
    fw = (AuditLog.query
          .filter(AuditLog.action.in_(["ip_blocked", "ip_unblocked", "ip_reblocked",
                                       "ip_whitelisted", "ip_unwhitelisted"]),
                  AuditLog.detail.like("'" + ip + "'%"))
          .order_by(AuditLog.created_at.desc()).limit(12).all())
    # WHO did it: the analyst's username, or None for the Response agent (auto)
    unames = {u.id: u.username for u in User.query.all()}
    return [{"action": a.action, "detail": a.detail, "by": unames.get(a.user_id),
             "created_at": a.created_at.isoformat() if a.created_at else None} for a in fw]


def _decision_log(e):
    """This event's own dismiss / reopen decisions, so they appear in the
    Response history alongside the firewall block/unblock rows. Matched on the
    'event #<id> ' prefix written by the decision endpoint (the trailing space
    keeps #61 from matching #619)."""
    rows = (AuditLog.query
            .filter(AuditLog.action.in_(["event_dismissed", "event_reopened"]),
                    AuditLog.detail.like("event #%d %%" % e.id))
            .order_by(AuditLog.created_at.desc()).limit(12).all())
    unames = {u.id: u.username for u in User.query.all()}
    return [{"action": a.action, "detail": a.detail, "by": unames.get(a.user_id),
             "created_at": a.created_at.isoformat() if a.created_at else None} for a in rows]


def _attack_evidence(e):
    """Deterministic 'why is this an attack' evidence for an Event (matched rule
    + the exact suspicious token from the raw logs). Implemented in
    app/services/attack_evidence.py so the same justification is reused by the
    high-risk alert email."""
    from app.services.attack_evidence import attack_evidence
    return attack_evidence(e.attack_type, e.raw_log_sample, rule=e.rule,
                           mitre=e.mitre_techniques, log_count=e.log_count)


def _lateral_movement(e):
    """If the attack's SOURCE IP is a known internal asset, flag possible
    lateral movement / a compromised host: an internal machine in the inventory
    should not itself be generating attack traffic. Uses the asset inventory as
    the source of truth for 'known internal host'."""
    from app.enrichment.asset_assessment import Asset
    a = Asset.query.filter_by(ip=e.source_ip).first() if e.source_ip else None
    if a and e.risk in ("high", "uncertain"):
        return {"flag": True, "asset": a.name or a.ip,
                "owner": a.owner, "criticality": a.criticality}
    return {"flag": False}


@api.get("/events/<int:event_id>")
@login_required
def event_detail(event_id):
    e = Event.query.get_or_404(event_id)
    d = e.to_dict()
    # firewall block/unblock for the source IP, plus this event's own dismiss /
    # reopen decisions, newest first
    d["response_log"] = sorted(
        _response_log(e.source_ip) + _decision_log(e),
        key=lambda r: r["created_at"] or "", reverse=True)
    d["source_blocked"] = e.source_ip in _blocked_ip_set()
    _wl = Whitelist.query.filter_by(ip=e.source_ip).first() if e.source_ip else None
    d["source_whitelisted"] = _wl is not None
    d["whitelist_reason"] = _wl.reason if _wl else None
    # the CASE ticket (T-xx) this event belongs to: the ticket that directly
    # holds it, otherwise the ticket of its attack chain. Also expose that
    # ticket's real status so the detail page shows the same vocabulary as the
    # Ticket Queue (queue/assigned/in_progress/closed), not the legacy per-event one.
    _tk = db.session.execute(
        db.text("SELECT ticket_id FROM ticket_events WHERE event_id=:eid ORDER BY ticket_id DESC LIMIT 1"),
        {"eid": e.id}).fetchone()
    _tid = _tk[0] if _tk else None
    if _tid is None and e.chain_id:
        _ct = Ticket.query.filter_by(chain_id=e.chain_id).order_by(Ticket.id.desc()).first()
        _tid = _ct.id if _ct else None
    d["ticket_id"] = _tid
    d["case_status"] = (Ticket.query.get(_tid).status if _tid else None)
    d["attack_evidence"] = _attack_evidence(e)
    d["lateral_movement"] = _lateral_movement(e)
    # the FULL set of log lines behind this event (raw_log_sample is only a
    # 20-line cut): re-run the event's own detection-rule query against ES for
    # this source inside the event's window, oldest first, capped at 500. Falls
    # back to the stored sample when ES or the rule definition is unavailable.
    d["full_logs"] = None
    full_msgs = None
    # ?light=1 is the page's quiet 10-second re-check (notes / status only):
    # skip the Elasticsearch round-trip for that
    light = request.args.get("light") in ("1", "true")
    if e.first_seen and e.source_ip and e.rule and not light:
        try:
            from app.services.siem_service import siem_service
            from datetime import timedelta as _td
            rule_q = next((r.get("query") for r in siem_service._rule_defs()
                           if r.get("name") == e.rule), None)
            if rule_q:
                rows, _tot = siem_service.search_raw_logs(
                    q=rule_q, source_ip=e.source_ip, start=e.first_seen,
                    end=(e.last_seen or e.first_seen) + _td(minutes=1),
                    page=1, per=500, order="asc")
                if rows:
                    d["full_logs"] = [{"t": r.get("timestamp"), "m": r.get("message") or ""}
                                      for r in rows]
                    d["full_logs_total"] = _tot
                    full_msgs = [x["m"] for x in d["full_logs"]]
        except Exception:
            pass   # ES unavailable: the page shows the stored sample
    from app.services.attack_evidence import annotate_logs
    d["log_breakdown"] = annotate_logs(full_msgs or e.raw_log_sample, limit=500)
    # the attack chain this event sits in, for the chain strip on the page
    _ch = AttackChain.query.get(e.chain_id) if e.chain_id else None
    d["chain"] = ({"id": _ch.id, "stages": _ch.stages or [], "predicted_next": _ch.predicted_next,
                   "highest_risk": _ch.highest_risk,
                   "first_seen": _ch.first_seen.isoformat() if _ch.first_seen else None,
                   "last_seen": _ch.last_seen.isoformat() if _ch.last_seen else None,
                   # the events behind the stages, so each node on the strip can
                   # open its event directly
                   "events": [{"id": x.id, "attack_type": x.attack_type, "status": x.status, "risk": x.risk,
                               "first_seen": x.first_seen.isoformat() if x.first_seen else None}
                              for x in _ch.events]}
                  if _ch else None)
    # ticketing: analyst notes, assignee, who closed it + the analyst roster for
    # the "assign to" picker.
    unames = {u.id: u.username for u in User.query.all()}
    d["closed_by_name"] = unames.get(e.closed_by)
    d["assigned_to_name"] = unames.get(e.assigned_to)
    d["notes"] = [{**n.to_dict(), "username": unames.get(n.user_id),
                   "deleted_by_name": unames.get(n.deleted_by)}
                  for n in EventNote.query.filter_by(event_id=e.id).order_by(EventNote.id).all()]
    d["team"] = _ticket_team()
    return jsonify(d)


@api.post("/events/<int:event_id>/notes")
@login_required
def add_event_note(event_id):
    """Add a free-text note/comment to an event (any signed-in analyst)."""
    e = Event.query.get_or_404(event_id)
    text = (request.get_json(force=True).get("text") or "").strip()
    if not text:
        return jsonify({"error": "note cannot be empty"}), 400
    n = EventNote(event_id=e.id, user_id=current_user.id, text=text[:2000])
    db.session.add(n)
    db.session.commit()
    return jsonify({"ok": True, "note": {**n.to_dict(), "username": current_user.username}}), 201


@api.patch("/events/<int:event_id>/notes/<int:note_id>")
@login_required
def edit_event_note(event_id, note_id):
    """Edit your OWN note (same rule as ticket comments)."""
    n = EventNote.query.filter_by(id=note_id, event_id=event_id).first_or_404()
    if n.user_id != current_user.id:
        return jsonify({"error": "you can only edit your own notes"}), 403
    if n.deleted_at:
        return jsonify({"error": "this note was deleted"}), 400
    text = (request.get_json(force=True).get("text") or "").strip()
    if not text:
        return jsonify({"error": "note cannot be empty"}), 400
    n.text = text[:2000]
    n.edited_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "note": {**n.to_dict(), "username": current_user.username}})


@api.delete("/events/<int:event_id>/notes/<int:note_id>")
@login_required
def delete_event_note(event_id, note_id):
    """Delete your OWN note. Soft delete: the row stays as a tombstone that
    shows who removed it and when (the text is cleared), so nothing vanishes
    from the record silently."""
    n = EventNote.query.filter_by(id=note_id, event_id=event_id).first_or_404()
    if n.user_id != current_user.id:
        return jsonify({"error": "you can only delete your own notes"}), 403
    if n.deleted_at:
        return jsonify({"error": "this note was already deleted"}), 400
    n.deleted_at = datetime.utcnow()
    n.deleted_by = current_user.id
    n.text = ""
    db.session.commit()
    return jsonify({"ok": True, "note": {**n.to_dict(), "username": current_user.username,
                                         "deleted_by_name": current_user.username}})


@api.post("/events/<int:event_id>/ticket")
@login_required
def update_ticket(event_id):
    """Update an event's ticket: status (open|in_progress|closed), assignee, and
    a close note when closing. Any signed-in analyst can work a ticket."""
    e = Event.query.get_or_404(event_id)
    data = request.get_json(force=True)
    if "status" in data:
        st = data.get("status")
        if st not in ("open", "in_progress", "closed"):
            return jsonify({"error": "invalid status"}), 400
        e.ticket_status = st
        if st == "closed":
            e.closed_at = datetime.utcnow()
            e.closed_by = current_user.id
            note = (data.get("note") or "").strip()[:500]
            if note:
                e.close_note = note
        else:
            e.closed_at = None
            e.closed_by = None
    if "assigned_to" in data:
        aid = data.get("assigned_to")
        if aid in (None, "", 0, "0"):
            e.assigned_to = None
        else:
            u = User.query.get(int(aid))
            e.assigned_to = u.id if u else None
    db.session.commit()
    unames = {u.id: u.username for u in User.query.all()}
    return jsonify({"ok": True, "ticket_status": e.ticket_status,
                    "assigned_to": e.assigned_to, "assigned_to_name": unames.get(e.assigned_to),
                    "closed_at": e.closed_at.isoformat() if e.closed_at else None,
                    "closed_by_name": unames.get(e.closed_by), "close_note": e.close_note})


@api.get("/tickets")
@login_required
def list_tickets():
    """Events as tickets for the board, grouped client-side by ticket_status.
    Recent-first; closed tickets are capped so the board stays usable."""
    unames = {u.id: u.username for u in User.query.all()}
    rows = Event.query.order_by(Event.id.desc()).limit(400).all()
    out = []
    for e in rows:
        out.append({"id": e.id, "attack_type": e.attack_type, "source_ip": e.source_ip,
                    "risk": e.risk, "ticket_status": e.ticket_status or "open",
                    "assigned_to_name": unames.get(e.assigned_to),
                    "last_seen": e.last_seen.isoformat() if e.last_seen else None,
                    "closed_at": e.closed_at.isoformat() if e.closed_at else None})
    return jsonify(out)


# ===================== Case tickets =====================
# The Case model: one attacker / attack chain = one ticket that groups events.
# Auto-raised by ticket_service.auto_raise() (scheduler) or manually by analysts.

def _tk_act(t, text, user_id=None):
    # 900: "Closed — <reason>\n<note>" must keep a full 500-char closing note
    db.session.add(TicketActivity(ticket_id=t.id, user_id=user_id, text=text[:900]))


def _notify(user_id, kind, ref_id, text):
    """In-app bell notification (replaces the earlier email-per-assignment)."""
    db.session.add(Notification(user_id=user_id, kind=kind, ref_id=ref_id, text=text[:300]))


def _ticket_team():
    """Active users who hold the Tickets permission: the only people a case can
    be assigned to or who can be @mentioned on it, since anyone else could not
    open the ticket the notification points at."""
    return [{"id": u.id, "username": u.username}
            for u in User.query.filter_by(is_active=True).order_by(User.username).all()
            if u.has_cap("approve_events")]


def _notify_all(kind, ref_id, text, exclude_id=None):
    """One bell notification for EVERY active analyst/manager (e.g. a new
    ticket was raised) — the actor themselves is skipped."""
    for u in User.query.filter_by(is_active=True).all():
        if exclude_id is not None and u.id == exclude_id:
            continue
        _notify(u.id, kind, ref_id, text)


# shown in the UI as a prompt when a ticket has no description yet; must NEVER
# be printed verbatim in a report, so reports treat it as empty
_DESC_PLACEHOLDER = "(Add your assessment here.)"


def _clean_desc(d):
    """A ticket description for a REPORT: the placeholder prompt becomes empty."""
    d = (d or "").strip()
    return "" if d == _DESC_PLACEHOLDER else d


def _tk_json(t, unames, deep=False):
    d = t.to_dict(deep=deep)
    d["assignee_name"] = unames.get(t.assignee_id)
    d["closed_by_name"] = unames.get(t.closed_by)
    d["blocked"] = bool(t.source_ip) and BlockedIP.query.filter_by(ip=t.source_ip, active=True).count() > 0
    # asset: prefer the enrichment snapshot on the event; fall back to the live
    # asset inventory keyed by the events' destination IP (real data either way)
    asset = None
    for e in t.events:
        if e.asset_info and (e.asset_info.get("name") or e.asset_info.get("ip")):
            asset = e.asset_info
            break
    if not asset or not asset.get("name"):
        from app.enrichment.asset_assessment import Asset, resolve_dest_ip
        dests = {resolve_dest_ip(e.dest_ip) for e in t.events if e.dest_ip}
        for ip in dests:
            row = Asset.query.filter_by(ip=ip).first()
            if row:
                asset = row.to_dict()
                break
    d["asset"] = asset or {}
    if deep and t.chain_id:
        ch = AttackChain.query.get(t.chain_id)
        d["chain"] = ch.to_dict() if ch else None
    return d


@api.get("/cases")
@login_required
def list_cases():
    """Ticket queue with the approved filters: status (open default), risk,
    assignee (username or __none), q, opened date, pagination."""
    q = Ticket.query
    st = (request.args.get("status") or "open").strip()
    if st == "open":
        q = q.filter(Ticket.status != "closed")
    elif st != "all" and st in TICKET_STATUSES:
        q = q.filter(Ticket.status == st)
    who = (request.args.get("assignee") or "").strip()
    if who == "__none":
        q = q.filter(Ticket.assignee_id.is_(None))
    elif who:
        u = User.query.filter_by(username=who).first()
        q = q.filter(Ticket.assignee_id == (u.id if u else -1))
    day = (request.args.get("date") or "").strip()
    if day:
        try:
            d0 = datetime.fromisoformat(day)
            q = q.filter(Ticket.created_at >= d0,
                         Ticket.created_at < d0.replace(hour=23, minute=59, second=59))
        except ValueError:
            pass
    rows = q.order_by(Ticket.created_at.desc()).all()

    risk = (request.args.get("risk") or "").strip()
    if risk in ("high", "uncertain", "low"):
        rows = [t for t in rows if t.risk() == risk]
    text = (request.args.get("q") or "").strip().lower()
    unames = {u.id: u.username for u in User.query.all()}
    if text:
        def hay(t):
            return (" ".join(["t-%d" % t.id, t.title or "", t.source_ip or "",
                              unames.get(t.assignee_id) or ""])).lower()
        rows = [t for t in rows if text in hay(t)]

    # triage order: queue > assigned > in_progress, closed last; newest first inside
    order = {"queue": 0, "assigned": 1, "in_progress": 2, "closed": 3}
    rows.sort(key=lambda t: (order.get(t.status, 9),))

    per = max(1, min(2000, int(request.args.get("per", 10))))
    page = max(1, int(request.args.get("page", 1)))
    pages = max(1, (len(rows) + per - 1) // per)
    page = min(page, pages)
    items = rows[(page - 1) * per: page * per]

    workload = {u.username: 0 for u in User.query.filter_by(is_active=True).all()}
    unassigned = 0
    for t in Ticket.query.filter(Ticket.status != "closed").all():
        n = unames.get(t.assignee_id)
        if n and n in workload:
            workload[n] += 1
        elif not t.assignee_id:
            unassigned += 1
    return jsonify({"tickets": [_tk_json(t, unames) for t in items],
                    "total": len(rows), "page": page, "pages": pages,
                    "workload": workload, "unassigned": unassigned,
                    "open_total": Ticket.query.filter(Ticket.status != "closed").count()})


@api.post("/cases")
@login_required
def create_case():
    """Manual ticket. Title required; source IP, assignee, note, events optional."""
    data = request.get_json(force=True)
    title = (data.get("title") or "").strip()[:160]
    ip = (data.get("source_ip") or "").strip()[:45]
    if not title:
        return jsonify({"error": "title is required"}), 400
    # no source IP is fine: internal problems (a broken workstation, a policy
    # question) have no attacker address — but blocking obviously needs one
    if data.get("block") and not ip:
        return jsonify({"error": "cannot block at the firewall: no source IP given"}), 400
    # the description is the RAISER's own writing (not auto-generated); the AI
    # assessment is added on demand later via "Check with AI"
    t = Ticket(title=title, source_ip=ip or None, raised_by="manual",
               created_by=current_user.id, status="queue",
               description=(data.get("note") or "").strip()[:2000]
               or _DESC_PLACEHOLDER)
    aid = data.get("assignee_id")
    if aid:
        u = User.query.get(int(aid))
        if u:
            t.assignee_id = u.id
            t.status = "assigned"
    seen_ev = set()
    for eid in (data.get("event_ids") or []):
        try:
            eid = int(eid)
        except (TypeError, ValueError):
            continue
        if eid in seen_ev:            # a careless "188, 188" would double-insert
            continue                  # and violate the ticket_events PK -> 500
        seen_ev.add(eid)
        e = Event.query.get(eid)
        if e:
            t.events.append(e)
    db.session.add(t)
    db.session.flush()
    _tk_act(t, "Raised manually by %s" % current_user.username, current_user.id)
    _notify_all("ticket_raised", t.id,
                "%s raised ticket T-%d — %s" % (current_user.username, t.id, t.title or ""),
                exclude_id=current_user.id)
    if t.assignee_id:
        au = User.query.get(t.assignee_id)
        _tk_act(t, "Assigned to %s" % au.username, current_user.id)
        if au.id != current_user.id:
            _notify(au.id, "ticket_assigned", t.id,
                    "%s assigned ticket T-%d (%s) to you" % (current_user.username, t.id, t.title))
    blocked_now = False
    if data.get("block"):
        # optional immediate firewall block of the source (needs the block_ips capability)
        if current_user.has_cap("block_ips"):
            from app.agents.response import response_agent
            # don't stack a second active row if the IP is already blocked
            if not BlockedIP.query.filter_by(ip=ip, active=True).first():
                response_agent.block_ip(ip)
                db.session.add(BlockedIP(ip=ip, attack_type="manual ticket",
                                         blocked_by="analyst"))
                _audit_block("ip_blocked", ip, "manual ticket T-%d" % t.id)
            _tk_act(t, "Source IP blocked at creation", current_user.id)
            blocked_now = True
        else:
            _tk_act(t, "Block requested but not permitted for this account", current_user.id)
    db.session.commit()
    _audit("ticket_created", "created ticket T-%d '%s'" % (t.id, t.title))
    unames = {u.id: u.username for u in User.query.all()}
    out = _tk_json(t, unames)
    out["blocked"] = out["blocked"] or blocked_now
    return jsonify({"ok": True, "ticket": out}), 201


@api.get("/cases/<int:tid>")
@login_required
def case_detail(tid):
    t = Ticket.query.get_or_404(tid)
    unames = {u.id: u.username for u in User.query.all()}
    d = _tk_json(t, unames, deep=True)
    d["comments"] = [{**c.to_dict(), "username": unames.get(c.user_id), "mine": c.user_id == current_user.id,
                      "deleted_by_name": unames.get(c.deleted_by)}
                     for c in TicketComment.query.filter_by(ticket_id=t.id)
                                                 .order_by(TicketComment.created_at).all()]
    d["activity"] = [{**a.to_dict(), "username": unames.get(a.user_id)}
                     for a in TicketActivity.query.filter_by(ticket_id=t.id)
                                                  .order_by(TicketActivity.created_at).all()]
    d["team"] = _ticket_team()
    d["close_reasons"] = list(TICKET_CLOSE_REASONS)
    return jsonify(d)


@api.post("/cases/<int:tid>")
@login_required
def update_case(tid):
    """Assign / change status / close (with reason + note). Any signed-in analyst."""
    t = Ticket.query.get_or_404(tid)
    data = request.get_json(force=True)
    unames = {u.id: u.username for u in User.query.all()}

    if "description" in data:
        # the analyst edits their own writeup; the change is logged so the
        # history is preserved even though the field itself is overwritten
        new_desc = (data.get("description") or "").strip()[:2000]
        if new_desc and new_desc != (t.description or ""):
            t.description = new_desc
            _tk_act(t, "Description edited by %s" % current_user.username, current_user.id)
        db.session.commit()
        return jsonify({"ok": True, "ticket": _tk_json(t, unames, deep=True)})

    if "assignee_id" in data:
        aid = data.get("assignee_id")
        if aid in (None, "", 0, "0"):
            t.assignee_id = None
            # symmetric with assign (queue -> assigned): removing the owner sends
            # an "assigned" ticket back to the queue. In-progress/closed keep their
            # status (unassigning doesn't undo work already started).
            if t.status == "assigned":
                t.status = "queue"
            _tk_act(t, "Unassigned", current_user.id)
        else:
            u = User.query.get(int(aid))
            if not u:
                return jsonify({"error": "no such user"}), 400
            if not (u.is_active and u.has_cap("approve_events")):
                return jsonify({"error": f"{u.username} does not hold the Tickets permission"}), 400
            t.assignee_id = u.id
            if t.status == "queue":
                t.status = "assigned"
            _tk_act(t, "Assigned to %s" % u.username, current_user.id)
            _audit("ticket_assigned", "assigned ticket T-%d to '%s'" % (t.id, u.username))
            if u.id != current_user.id:
                _notify(u.id, "ticket_assigned", t.id,
                        "%s assigned ticket T-%d (%s) to you"
                        % (current_user.username, t.id, t.title))

    if "status" in data:
        st = data.get("status")
        if st not in TICKET_STATUSES:
            return jsonify({"error": "invalid status"}), 400
        if st == "queue":
            # back to the queue = up for grabs again, so drop the assignee
            if t.assignee_id:
                _tk_act(t, "Moved back to queue — unassigned", current_user.id)
            t.assignee_id = None
        if st == "in_progress" and not t.assignee_id:
            # whoever starts the work owns it: an in-progress case must have an
            # owner, so an unassigned ticket moved to In progress is assigned to
            # the person who moved it (a ticket that already has an owner keeps it)
            t.assignee_id = current_user.id
            _tk_act(t, "Started work — assigned to %s" % current_user.username, current_user.id)
            _audit("ticket_assigned", "assigned ticket T-%d to '%s' (started work)" % (t.id, current_user.username))
        if st == "closed" and t.status == "closed":
            pass   # already closed — a double-click must not re-stamp / re-log
        elif st == "closed":
            # closing always names a reason: one of the quick reasons, or a
            # written note (recorded under the reason "Other")
            reason = (data.get("reason") or "").strip()
            note = (data.get("note") or "").strip()[:500]
            if reason not in TICKET_CLOSE_REASONS:
                reason = "Other" if note else ""
            if not reason:
                return jsonify({"error": "choose a reason or write a closing note"}), 400
            need = _fw_change_needed(t, reason)
            if need and not current_user.has_cap("block_ips"):
                return jsonify({"error": "closing as %s would %s %s, which needs the Firewall Blocks "
                                         "permission. Ask a firewall holder to close it, or choose another reason."
                                         % (reason.lower(), need, t.source_ip)}), 403
            effects = _close_effects(t, reason)
            t.status = "closed"
            t.closed_at = datetime.utcnow()
            t.closed_by = current_user.id
            t.close_reason = reason
            t.close_note = note
            # the note goes on its own line so the Activity timeline keeps the
            # full closing text of EVERY close (the Resolution card only shows
            # the latest one)
            _tk_act(t, "Closed — %s" % reason + ("\n" + note if note else "")
                    + "".join("\n" + x for x in effects), current_user.id)
            _audit("ticket_closed", "closed ticket T-%d (%s)" % (t.id, reason))
        elif t.status == "closed" and st != "closed":
            # REOPEN: wipe the WHOLE resolution (close_note too — it was
            # lingering into the exported PDF of a now-open ticket), and undo
            # the false-positive dismissals so the analyst can act on the
            # events again instead of hitting a dead end
            t.status = st
            t.closed_at = None
            t.closed_by = None
            t.close_reason = None
            t.close_note = None
            reverted = 0
            for e in t.events:
                if e.status == "dismissed":
                    e.status = "awaiting"
                    reverted += 1
            _tk_act(t, "Reopened" + (" — %d event(s) restored to awaiting" % reverted
                                     if reverted else ""), current_user.id)
            _audit("ticket_status", "reopened ticket T-%d to '%s'" % (t.id, st.replace("_", " ")))
        else:
            t.status = st
            _tk_act(t, "Status changed to %s" % st.replace("_", " "), current_user.id)
            _audit("ticket_status", "moved ticket T-%d to '%s'" % (t.id, st.replace("_", " ")))

    db.session.commit()
    return jsonify({"ok": True, "ticket": _tk_json(t, unames)})


@api.post("/cases/<int:tid>/comments")
@login_required
def add_case_comment(tid):
    t = Ticket.query.get_or_404(tid)
    data = request.get_json(force=True)
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "comment cannot be empty"}), 400
    parent_id = data.get("parent_id")
    if parent_id:
        parent = TicketComment.query.filter_by(id=int(parent_id), ticket_id=t.id).first()
        parent_id = parent.id if parent else None
    c = TicketComment(ticket_id=t.id, user_id=current_user.id, text=text[:2000], parent_id=parent_id)
    db.session.add(c)
    _tk_act(t, "Replied in discussion" if parent_id else "Comment added", current_user.id)
    # @mention -> in-app bell notification for the mentioned teammate
    import re as _re
    # the bell says who mentioned you and where; the note itself is read on the ticket
    for name in set(_re.findall(r"@(\w+)", text)):
        u = User.query.filter_by(username=name).first()
        if u and u.id != current_user.id and u.is_active and u.has_cap("approve_events"):
            _notify(u.id, "mention", t.id,
                    "%s mentioned you on ticket T-%d" % (current_user.username, t.id))
    db.session.commit()
    return jsonify({"ok": True, "comment": {**c.to_dict(), "username": current_user.username, "mine": True}}), 201


@api.patch("/cases/<int:tid>/comments/<int:cid>")
@login_required
def edit_case_comment(tid, cid):
    """Edit your own comment."""
    c = TicketComment.query.filter_by(id=cid, ticket_id=tid).first_or_404()
    if c.user_id != current_user.id:
        return jsonify({"error": "you can only edit your own comments"}), 403
    if c.deleted_at:
        return jsonify({"error": "this note was deleted"}), 400
    text = (request.get_json(force=True).get("text") or "").strip()
    if not text:
        return jsonify({"error": "comment cannot be empty"}), 400
    c.text = text[:2000]
    c.edited_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "comment": {**c.to_dict(), "username": current_user.username, "mine": True}})


@api.delete("/cases/<int:tid>/comments/<int:cid>")
@login_required
def delete_case_comment(tid, cid):
    """Delete a note: only its AUTHOR may (the AI notes have no author, so any
    analyst may remove them). Soft delete: the row stays as a tombstone that
    shows who removed it and when, replies stay attached to it, and the text
    is cleared."""
    c = TicketComment.query.filter_by(id=cid, ticket_id=tid).first_or_404()
    is_ai = c.user_id is None
    if not (is_ai or c.user_id == current_user.id):
        return jsonify({"error": "you can only delete your own notes"}), 403
    if c.deleted_at:
        return jsonify({"error": "this note was already deleted"}), 400
    c.deleted_at = datetime.utcnow()
    c.deleted_by = current_user.id
    c.text = ""
    _tk_act(Ticket.query.get(tid), "A discussion note was deleted", current_user.id)
    db.session.commit()
    return jsonify({"ok": True})


@api.post("/cases/<int:tid>/fw")
@login_required
def case_firewall(tid):
    """Firewall action straight from the ticket: block | unblock | reblock.
    Optional description lands in the ticket activity; everything is audited.
    (The UI asks for the account password first, same as the Firewall page.)"""
    deny = _require_cap("block_ips")
    if deny:
        return deny
    t = Ticket.query.get_or_404(tid)
    if not t.source_ip:
        return jsonify({"error": "ticket has no source IP"}), 400
    data = request.get_json(force=True)
    action = data.get("action")
    desc = (data.get("description") or "").strip()[:300]
    from app.agents.response import response_agent
    ip = t.source_ip
    if action == "block":
        b = BlockedIP.query.filter_by(ip=ip, active=True).first()
        if b:
            return jsonify({"error": "IP is already blocked"}), 409
        response_agent.block_ip(ip)
        # an address that was blocked before and released keeps its history:
        # reactivate that record (audited as a re-block) instead of adding a row
        old_row = BlockedIP.query.filter_by(ip=ip).order_by(BlockedIP.id.desc()).first()
        if old_row:
            old_row.active = True
            _audit_block("ip_reblocked", ip, desc or ("from ticket T-%d" % t.id))
            _tk_act(t, "IP blocked again from ticket" + (" — " + desc if desc else ""), current_user.id)
        else:
            db.session.add(BlockedIP(ip=ip, attack_type=desc or ("ticket T-%d" % t.id),
                                     blocked_by="analyst"))
            _audit_block("ip_blocked", ip, desc or ("from ticket T-%d" % t.id))
            _tk_act(t, "IP blocked from ticket" + (" — " + desc if desc else ""), current_user.id)
    elif action == "unblock":
        b = BlockedIP.query.filter_by(ip=ip, active=True).first()
        if not b:
            return jsonify({"error": "IP is not currently blocked"}), 409
        response_agent.unblock_ip(ip)
        b.active = False
        _audit_block("ip_unblocked", ip, desc or ("from ticket T-%d" % t.id))
        _tk_act(t, "IP unblocked from ticket" + (" — " + desc if desc else ""), current_user.id)
    elif action == "reblock":
        b = BlockedIP.query.filter_by(ip=ip).order_by(BlockedIP.id.desc()).first()
        if not b or b.active:
            return jsonify({"error": "nothing to re-block"}), 409
        b.active = True
        response_agent.block_ip(ip)
        _audit_block("ip_reblocked", ip, desc or ("from ticket T-%d" % t.id))
        _tk_act(t, "IP re-blocked from ticket" + (" — " + desc if desc else ""), current_user.id)
    else:
        return jsonify({"error": "invalid action"}), 400
    db.session.commit()
    unames = {u.id: u.username for u in User.query.all()}
    return jsonify({"ok": True, "ticket": _tk_json(t, unames)})


@api.post("/cases/<int:tid>/false-positive")
@login_required
def case_false_positive(tid):
    """Mark the whole ticket a false positive: dismiss its awaiting events and
    close it with the (required) description."""
    deny = _require_cap("approve_events")
    if deny:
        return deny
    t = Ticket.query.get_or_404(tid)
    desc = (request.get_json(force=True).get("description") or "").strip()[:500]
    if not desc:
        return jsonify({"error": "a description is required"}), 400
    dismissed = 0
    for e in t.events:
        if e.status == "awaiting":
            e.status = "dismissed"
            db.session.add(Decision(event_id=e.id, user_id=current_user.id,
                                    action="dismissed", label="false_positive"))
            dismissed += 1
    t.status = "closed"
    t.closed_at = datetime.utcnow()
    t.closed_by = current_user.id
    t.close_reason = "False positive"
    t.close_note = desc
    _tk_act(t, "Marked false positive (%d event(s) dismissed)\n%s" % (dismissed, desc),
            current_user.id)
    _audit("ticket_closed", "closed ticket T-%d (False positive)" % t.id)
    db.session.commit()
    unames = {u.id: u.username for u in User.query.all()}
    return jsonify({"ok": True, "ticket": _tk_json(t, unames)})


@api.post("/cases/<int:tid>/analyze")
@login_required
def case_analyze(tid):
    """Attach the ticket to detection data for its source IP (chain + events)
    and rebuild title/description from the stored AI investigation output."""
    t = Ticket.query.get_or_404(tid)
    from app.services.ticket_service import _title_for, _description_for
    added = 0
    chain = AttackChain.query.filter_by(source_ip=t.source_ip).order_by(AttackChain.id.desc()).first()
    have = {e.id for e in t.events}
    excl = set(t.excluded_event_ids or [])   # events the analyst detached: never re-add
    if chain:
        t.chain_id = chain.id
        for e in (chain.events or []):
            if e.id not in have and e.id not in excl:
                t.events.append(e)
                have.add(e.id)
                added += 1
    for e in Event.query.filter_by(source_ip=t.source_ip).all():
        if e.id not in have and e.id not in excl and e.chain_id is None:
            t.events.append(e)
            have.add(e.id)
            added += 1
    # the analyst's own description is NEVER overwritten. The AI assessment is
    # APPENDED to the discussion as a timestamped note (marked [[AI]]) so both
    # the human's writing and every AI check are preserved side by side.
    if t.events:
        ai_text = _description_for(t.events, chain)
        note = ("AI analysis run: linked %s%d event(s); assessment added as a note%s"
                % (("chain #%d and " % chain.id) if chain else "", added,
                   (" (%d detached event(s) left out)" % len(excl)) if excl else ""))
    else:
        # no events yet — DON'T make the analyst wait for a poll; run the
        # grounded assistant on whatever we have (source IP + their description)
        from app.services.chat_service import answer_question
        prompt = ("Assess the threat for this case. Source IP: %s. Analyst note: %s"
                  % (t.source_ip or "none", (t.description or "").strip() or "(none)"))
        res = answer_question(prompt)
        ai_text = res.get("answer") if res.get("ok") else (
            "The AI could not reach the language model right now. There is no "
            "detection data linked to this case yet — attach events, or wait "
            "for the next poll, and run the check again.")
        note = "AI check run (no linked events yet); assessment added as a note"
    db.session.add(TicketComment(ticket_id=t.id, user_id=None,
                                 text=("[[AI]]" + (ai_text or ""))[:2000]))
    _tk_act(t, note, current_user.id)
    db.session.commit()
    unames = {u.id: u.username for u in User.query.all()}
    return jsonify({"ok": True, "ticket": _tk_json(t, unames, deep=True)})


@api.get("/cases/<int:tid>/report")
@login_required
def case_report(tid):
    """Export the whole case as one PDF dossier: ticket summary + kill chain +
    the full detail page of every SELECTED event (?events=1,2 — empty = all)."""
    from app.services.report_service import generate_chain_report
    t = Ticket.query.get_or_404(tid)
    events = sorted(t.events, key=lambda e: e.first_seen or datetime.utcnow())
    sel = (request.args.get("events") or "").strip()
    if sel:
        want = {int(x) for x in sel.split(",") if x.strip().isdigit()}
        detail_events = [e for e in events if e.id in want]
    else:
        detail_events = events
    chain = AttackChain.query.get(t.chain_id) if t.chain_id else None
    stages = (chain.stages or []) if chain else [
        {"phase": "—", "attack_type": e.attack_type, "mitre": e.mitre_techniques or [],
         "log_count": e.log_count, "risk": e.risk} for e in events]
    unames = {u.id: u.username for u in User.query.all()}
    state = {
        "report_ref": "T-%d — %s" % (t.id, t.title or "case"),
        "source_ip": t.source_ip,
        "stage_count": (chain.stage_count if chain else len(events)) or len(events),
        "chain_risk": t.risk(),
        "first_seen": (events[0].first_seen.isoformat() if events and events[0].first_seen
                       else (t.created_at.isoformat() if t.created_at else None)),
        "last_seen": (events[-1].last_seen.isoformat() if events and events[-1].last_seen else None),
        "chain_assessment": _clean_desc(t.description) or None,
        "stages": stages,
        "predicted_next": chain.predicted_next if chain else None,
        "events": [{"id": e.id, "attack_type": e.attack_type, "risk": e.risk,
                    "confidence": e.confidence, "status": e.status,
                    "log_count": e.log_count} for e in events],
        "event_details": [_state_from_event(e) for e in detail_events],
        "ticket": {"id": t.id, "title": t.title, "status": t.status,
                   "owner": unames.get(t.assignee_id) or "unassigned",
                   "created_at": t.created_at.isoformat() if t.created_at else None,
                   "close_reason": t.close_reason, "close_note": t.close_note,
                   "closed_by": unames.get(t.closed_by),
                   "closed_at": t.closed_at.isoformat() if t.closed_at else None},
    }
    path = generate_chain_report({**state, "generated_by": current_user.username})
    if not os.path.isabs(path):
        path = os.path.join(_PROJECT_ROOT, path)
    as_att = request.args.get("download") == "1"
    return send_file(path, as_attachment=as_att, download_name=os.path.basename(path))


@api.delete("/cases/<int:tid>")
@login_required
def delete_case(tid):
    """Delete a ticket (any analyst; every delete is audited). Its events are
    freed, so the next auto-raise sweep can re-open them if still actionable."""
    t = Ticket.query.get_or_404(tid)
    TicketComment.query.filter_by(ticket_id=t.id).delete()
    TicketActivity.query.filter_by(ticket_id=t.id).delete()
    # clear EVERY notification pointing at this ticket — including the
    # team-wide "ticket_raised" broadcast — so nobody is left with a bell
    # entry that 404s when clicked
    Notification.query.filter(
        Notification.ref_id == t.id,
        Notification.kind.in_(["ticket_assigned", "mention", "ticket_raised"])
    ).delete(synchronize_session=False)
    t.events = []            # clear the association rows
    db.session.delete(t)
    db.session.commit()
    _audit("ticket_deleted", "deleted ticket T-%d" % tid)
    return jsonify({"ok": True})


@api.post("/cases/auto-raise")
@login_required
def cases_auto_raise():
    """Manual trigger for the auto-raise sweep (also runs from the scheduler)."""
    from app.services.ticket_service import auto_raise
    n = auto_raise()
    return jsonify({"ok": True, "created": n})


@api.get("/notifications")
@login_required
def list_notifications():
    """The signed-in user's bell feed: latest 30 + unread count."""
    # id tiebreak: several notifications created in the same second must still
    # come newest-first (created_at alone let same-second rows swap order)
    rows = (Notification.query.filter_by(user_id=current_user.id)
            .order_by(Notification.id.desc()).limit(30).all())
    unread = Notification.query.filter_by(user_id=current_user.id, read=False).count()
    return jsonify({"items": [n.to_dict() for n in rows], "unread": unread})


@api.post("/notifications/read")
@login_required
def read_notifications():
    """Mark all of the signed-in user's notifications as read."""
    Notification.query.filter_by(user_id=current_user.id, read=False)\
        .update({"read": True})
    db.session.commit()
    return jsonify({"ok": True})


@api.post("/notifications/<int:nid>/read")
@login_required
def read_one_notification(nid):
    """Mark ONE notification read — used when the user actually clicks it."""
    n = Notification.query.filter_by(id=nid, user_id=current_user.id).first_or_404()
    n.read = True
    db.session.commit()
    unread = Notification.query.filter_by(user_id=current_user.id, read=False).count()
    return jsonify({"ok": True, "unread": unread})


@api.post("/notifications/<int:nid>/toggle")
@login_required
def toggle_notification(nid):
    """Right-click toggle: flip one notification between read and unread."""
    n = Notification.query.filter_by(id=nid, user_id=current_user.id).first_or_404()
    n.read = not n.read
    db.session.commit()
    unread = Notification.query.filter_by(user_id=current_user.id, read=False).count()
    return jsonify({"ok": True, "read": bool(n.read), "unread": unread})


@api.post("/notifications/toggle-all")
@login_required
def toggle_all_notifications():
    """One-click mark ALL of my notifications read (read=true) or unread."""
    want = bool(request.get_json(force=True).get("read"))
    Notification.query.filter_by(user_id=current_user.id).update({"read": want})
    db.session.commit()
    unread = Notification.query.filter_by(user_id=current_user.id, read=False).count()
    return jsonify({"ok": True, "unread": unread})


# ===================== Team chat (lives in Buddy) =====================
_CHAT_UPLOAD_DIR = os.path.join("data", "uploads", "chat")


def _my_groups():
    return [g for g in ChatGroup.query.all() if current_user.id in (g.member_ids or [])]


def _visible_groups():
    """Groups I'm in PLUS groups I left/was removed from (read-only history,
    kept until I delete the chat — WhatsApp behaviour)."""
    return [g for g in ChatGroup.query.all()
            if current_user.id in (g.member_ids or []) or current_user.id in (g.left_ids or [])]


def _sys_msg(gid, text):
    """A system line inside the group thread ('x left the group', ...).
    sender_id=None marks it as system; the UI renders it centred and grey."""
    db.session.add(ChatMessage(sender_id=None, group_id=gid, text=text[:2000]))


@api.get("/chat/conversations")
@login_required
def chat_conversations():
    """WhatsApp-style: only conversations WITH history are listed; teammates you
    have never chatted with come back as 'contacts' for the + picker."""
    users = User.query.filter(User.id != current_user.id, User.is_active.is_(True)).all()
    convs, contacts = [], []
    for u in users:
        last = (ChatMessage.query
                .filter(db.or_(db.and_(ChatMessage.sender_id == current_user.id, ChatMessage.peer_id == u.id),
                               db.and_(ChatMessage.sender_id == u.id, ChatMessage.peer_id == current_user.id)))
                .order_by(ChatMessage.created_at.desc()).first())
        if last is None:
            contacts.append({"id": u.id, "name": u.username})
            continue
        unread = ChatMessage.query.filter_by(sender_id=u.id, peer_id=current_user.id, read=False).count()
        convs.append({"kind": "dm", "id": u.id, "name": u.username, "unread": unread,
                      "last": {**last.to_dict(),
                               "sender": (current_user.username if last.sender_id == current_user.id
                                          else u.username)}})
    seen = {s.group_id: (s.last_read_id or 0)
            for s in ChatGroupSeen.query.filter_by(user_id=current_user.id).all()}
    unread_groups = 0
    for g in _visible_groups():
        left = current_user.id in (g.left_ids or [])
        last = (ChatMessage.query.filter_by(group_id=g.id)
                .order_by(ChatMessage.created_at.desc()).first())
        unames = {u2.id: u2.username for u2 in User.query.all()}
        g_unread = 0
        if not left:   # a left chat is read-only history: never counts as unread
            g_unread = (ChatMessage.query
                        .filter(ChatMessage.group_id == g.id,
                                ChatMessage.id > seen.get(g.id, 0),
                                ChatMessage.sender_id != current_user.id,
                                ChatMessage.deleted.is_(False)).count())
        unread_groups += g_unread
        convs.append({"kind": "group", "id": g.id, "name": g.name,
                      "members": g.member_ids or [], "admin": g.created_by,
                      "left": left, "unread": g_unread,
                      "last": ({**last.to_dict(),
                                "sender": (unames.get(last.sender_id) if last.sender_id else None)}
                               if last else None)})
    unread_total = (ChatMessage.query.filter_by(peer_id=current_user.id, read=False).count()
                    + unread_groups)
    return jsonify({"conversations": convs, "contacts": contacts, "unread_total": unread_total})


@api.patch("/chat/messages/<int:mid>")
@login_required
def chat_edit_message(mid):
    m = ChatMessage.query.get_or_404(mid)
    if m.sender_id != current_user.id or m.deleted:
        return jsonify({"error": "you can only edit your own messages"}), 403
    text = (request.get_json(force=True).get("text") or "").strip()[:2000]
    if not text:
        return jsonify({"error": "empty message"}), 400
    m.text = text
    m.edited_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "message": m.to_dict()})


@api.delete("/chat/messages/<int:mid>")
@login_required
def chat_delete_message(mid):
    m = ChatMessage.query.get_or_404(mid)
    if m.sender_id != current_user.id:
        return jsonify({"error": "you can only delete your own messages"}), 403
    m.deleted = True
    m.pinned = False
    db.session.commit()
    return jsonify({"ok": True})


@api.post("/chat/messages/<int:mid>/pin")
@login_required
def chat_pin_message(mid):
    m = ChatMessage.query.get_or_404(mid)
    if m.deleted:
        return jsonify({"error": "cannot pin a deleted message"}), 400
    m.pinned = not m.pinned
    db.session.commit()
    return jsonify({"ok": True, "pinned": bool(m.pinned)})


@api.post("/chat/dm/<int:uid>/read")
@login_required
def chat_dm_read(uid):
    """Mark a DM read (all incoming) or unread (latest incoming) — WhatsApp style."""
    want = bool(request.get_json(force=True).get("read"))
    q = ChatMessage.query.filter_by(sender_id=uid, peer_id=current_user.id)
    if want:
        q.update({"read": True})
    else:
        last = q.order_by(ChatMessage.created_at.desc()).first()
        if last:
            last.read = False
    db.session.commit()
    return jsonify({"ok": True})


@api.delete("/chat/dm/<int:uid>")
@login_required
def chat_dm_delete(uid):
    """Delete the whole conversation with one teammate (both directions)."""
    n = (ChatMessage.query
         .filter(db.or_(db.and_(ChatMessage.sender_id == current_user.id, ChatMessage.peer_id == uid),
                        db.and_(ChatMessage.sender_id == uid, ChatMessage.peer_id == current_user.id)))
         .delete(synchronize_session=False))
    db.session.commit()
    return jsonify({"ok": True, "deleted": n})


def _leave_group(g):
    """Move me from members to ex-members (history stays readable, WhatsApp
    style); the longest-standing remaining member inherits admin."""
    _sys_msg(g.id, "%s left the group" % current_user.username)
    remaining = [m for m in (g.member_ids or []) if m != current_user.id]
    g.member_ids = remaining
    g.left_ids = (g.left_ids or []) + [current_user.id]
    if g.created_by == current_user.id and remaining:
        g.created_by = remaining[0]        # join order: the longest-standing member
        new_admin = User.query.get(remaining[0])
        _sys_msg(g.id, "%s is now the group admin" % (new_admin.username if new_admin else "?"))
        _notify(g.created_by, "chat_group", g.id,
                '%s left "%s" — you are the new group admin' % (current_user.username, g.name))
    db.session.commit()
    return jsonify({"ok": True, "action": "left", "admin": g.created_by})


def _hard_delete_group(g):
    ChatMessage.query.filter_by(group_id=g.id).delete(synchronize_session=False)
    ChatGroupSeen.query.filter_by(group_id=g.id).delete(synchronize_session=False)
    db.session.delete(g)
    db.session.commit()


@api.delete("/chat/groups/<int:gid>")
@login_required
def chat_group_delete(gid):
    """Admin deletes the whole group; an EX-member deletes their own view of
    the history; a plain member is treated as leaving."""
    g = ChatGroup.query.get_or_404(gid)
    if current_user.id in (g.left_ids or []):
        g.left_ids = [m for m in g.left_ids if m != current_user.id]
        ChatGroupSeen.query.filter_by(group_id=g.id, user_id=current_user.id).delete(synchronize_session=False)
        if not (g.member_ids or []) and not (g.left_ids or []):
            _hard_delete_group(g)          # nobody can see it any more
        else:
            db.session.commit()
        return jsonify({"ok": True, "action": "removed"})
    if current_user.id not in (g.member_ids or []):
        return jsonify({"error": "not a member"}), 403
    if g.created_by == current_user.id:
        _hard_delete_group(g)
        return jsonify({"ok": True, "action": "deleted"})
    return _leave_group(g)


@api.post("/chat/groups/<int:gid>/read")
@login_required
def chat_group_read(gid):
    """Mark a group read (marker -> latest message) or unread (latest incoming
    message becomes unread again) — mirrors the DM read/unread toggle."""
    g = ChatGroup.query.get_or_404(gid)
    if current_user.id not in (g.member_ids or []):
        return jsonify({"error": "not a member"}), 403
    want = bool(request.get_json(force=True).get("read"))
    row = ChatGroupSeen.query.filter_by(user_id=current_user.id, group_id=gid).first()
    if row is None:
        row = ChatGroupSeen(user_id=current_user.id, group_id=gid, last_read_id=0)
        db.session.add(row)
    if want:
        top = (ChatMessage.query.filter_by(group_id=gid)
               .order_by(ChatMessage.id.desc()).first())
        row.last_read_id = top.id if top else 0
    else:
        last_in = (ChatMessage.query
                   .filter(ChatMessage.group_id == gid,
                           ChatMessage.sender_id != current_user.id,
                           ChatMessage.deleted.is_(False))
                   .order_by(ChatMessage.id.desc()).first())
        if last_in:
            row.last_read_id = last_in.id - 1
    db.session.commit()
    return jsonify({"ok": True})


@api.post("/chat/groups/<int:gid>/admin")
@login_required
def chat_group_admin(gid):
    """Transfer group admin to another member (current admin only)."""
    g = ChatGroup.query.get_or_404(gid)
    if g.created_by != current_user.id:
        return jsonify({"error": "only the group admin can do that"}), 403
    new_admin = int(request.get_json(force=True).get("user_id") or 0)
    if new_admin not in (g.member_ids or []):
        return jsonify({"error": "that user is not a group member"}), 400
    g.created_by = new_admin
    na = User.query.get(new_admin)
    _sys_msg(g.id, "%s made %s the group admin" % (current_user.username,
                                                   na.username if na else "?"))
    _notify(new_admin, "chat_group", g.id,
            '%s made you the admin of "%s"' % (current_user.username, g.name))
    db.session.commit()
    return jsonify({"ok": True, "admin": new_admin})


@api.post("/chat/groups/<int:gid>/leave")
@login_required
def chat_group_leave(gid):
    """Anyone (admin included) can leave. WhatsApp behaviour: the chat stays in
    the leaver's list as read-only history until they delete it; if the admin
    leaves, admin passes to the longest-standing remaining member."""
    g = ChatGroup.query.get_or_404(gid)
    if current_user.id not in (g.member_ids or []):
        return jsonify({"error": "not a member"}), 403
    return _leave_group(g)


@api.post("/chat/groups/<int:gid>/members")
@login_required
def chat_group_add_members(gid):
    """Admin adds members; each one gets the same pop-out as at group creation."""
    g = ChatGroup.query.get_or_404(gid)
    if g.created_by != current_user.id:
        return jsonify({"error": "only the group admin can add members"}), 403
    add = [int(x) for x in (request.get_json(force=True).get("add") or [])]
    cur = list(g.member_ids or [])
    added = []
    unames = {u.id: u.username for u in User.query.all()}
    for uid in add:
        if uid in cur or uid not in unames:
            continue
        cur.append(uid)            # appended last = newest member (join order)
        added.append(uid)
        _notify(uid, "chat_group", g.id,
                '%s added you to the group "%s"' % (current_user.username, g.name))
    if not added:
        return jsonify({"error": "nobody new to add"}), 400
    g.member_ids = cur
    # someone who left and is re-added becomes a full member again
    g.left_ids = [m for m in (g.left_ids or []) if m not in added]
    _sys_msg(g.id, "%s added %s" % (current_user.username,
                                    ", ".join(unames[u] for u in added)))
    db.session.commit()
    return jsonify({"ok": True, "added": added, "members": g.member_ids})


@api.delete("/chat/groups/<int:gid>/members/<int:uid>")
@login_required
def chat_group_kick(gid, uid):
    """Admin removes a member (never themselves — they leave or delete instead)."""
    g = ChatGroup.query.get_or_404(gid)
    if g.created_by != current_user.id:
        return jsonify({"error": "only the group admin can remove members"}), 403
    if uid == current_user.id:
        return jsonify({"error": "leave or delete the group instead"}), 400
    if uid not in (g.member_ids or []):
        return jsonify({"error": "that user is not a group member"}), 400
    kicked = User.query.get(uid)
    g.member_ids = [m for m in g.member_ids if m != uid]
    # the removed member keeps read-only history (WhatsApp) until they delete it
    g.left_ids = (g.left_ids or []) + [uid]
    _sys_msg(g.id, "%s removed %s" % (current_user.username,
                                      kicked.username if kicked else ("user #%d" % uid)))
    _notify(uid, "chat_group", g.id,
            '%s removed you from the group "%s"' % (current_user.username, g.name))
    db.session.commit()
    return jsonify({"ok": True, "members": g.member_ids})


@api.get("/chat/search")
@login_required
def chat_search():
    """Search usernames AND message content across everything I can see."""
    q = (request.args.get("q") or "").strip().lower()
    if not q:
        return jsonify({"results": []})
    my_group_ids = [g.id for g in _visible_groups()]
    unames = {u.id: u.username for u in User.query.all()}
    gnames = {g.id: g.name for g in ChatGroup.query.all()}
    visible = (ChatMessage.query
               .filter(ChatMessage.deleted.is_(False))
               .filter(db.or_(ChatMessage.sender_id == current_user.id,
                              ChatMessage.peer_id == current_user.id,
                              ChatMessage.group_id.in_(my_group_ids) if my_group_ids else db.false()))
               .order_by(ChatMessage.created_at.desc()).limit(400).all())
    out = []
    for m in visible:
        hay = ((m.text or "") + " " + (m.file_name or "") + " " + (unames.get(m.sender_id) or "")).lower()
        if q in hay:
            if m.group_id:
                conv = {"kind": "group", "id": m.group_id, "name": gnames.get(m.group_id, "?")}
            else:
                other = m.peer_id if m.sender_id == current_user.id else m.sender_id
                conv = {"kind": "dm", "id": other, "name": unames.get(other, "?")}
            out.append({**m.to_dict(), "sender": unames.get(m.sender_id), "conv": conv})
        if len(out) >= 20:
            break
    return jsonify({"results": out})


@api.get("/chat/messages")
@login_required
def chat_messages():
    """Messages for one DM (?peer=<uid>) or group (?group=<gid>). Opening a DM
    marks its incoming messages read (like any messenger)."""
    peer = request.args.get("peer", type=int)
    group = request.args.get("group", type=int)
    if peer:
        q = (ChatMessage.query
             .filter(db.or_(db.and_(ChatMessage.sender_id == current_user.id, ChatMessage.peer_id == peer),
                            db.and_(ChatMessage.sender_id == peer, ChatMessage.peer_id == current_user.id)))
             .order_by(ChatMessage.created_at).limit(200))
        msgs = q.all()
        changed = False
        for m in msgs:
            if m.peer_id == current_user.id and not m.read:
                m.read = True
                changed = True
        if changed:
            db.session.commit()
    elif group:
        g = ChatGroup.query.get_or_404(group)
        is_member = current_user.id in (g.member_ids or [])
        if not is_member and current_user.id not in (g.left_ids or []):
            return jsonify({"error": "not a member of this group"}), 403
        msgs = (ChatMessage.query.filter_by(group_id=group)
                .order_by(ChatMessage.created_at).limit(200).all())
        # opening the group counts as reading it -> advance my read marker
        # (ex-members read history only; their marker no longer matters)
        if msgs and is_member:
            top = max(m.id for m in msgs)
            row = ChatGroupSeen.query.filter_by(user_id=current_user.id, group_id=group).first()
            if row is None:
                row = ChatGroupSeen(user_id=current_user.id, group_id=group, last_read_id=0)
                db.session.add(row)
            if top > (row.last_read_id or 0):
                row.last_read_id = top
                db.session.commit()
    else:
        return jsonify({"error": "peer or group required"}), 400
    unames = {u.id: u.username for u in User.query.all()}
    return jsonify({"messages": [{**m.to_dict(), "sender": unames.get(m.sender_id)} for m in msgs]})


@api.post("/chat/send")
@login_required
def chat_send():
    """Send a message (text and/or an already-uploaded attachment)."""
    data = request.get_json(force=True)
    text = (data.get("text") or "").strip()[:2000]
    fname = (data.get("file_name") or "").strip() or None
    fpath = (data.get("file_path") or "").strip() or None
    if not text and not fname:
        return jsonify({"error": "empty message"}), 400
    m = ChatMessage(sender_id=current_user.id, text=text or None,
                    file_name=fname, file_path=fpath)
    pid = data.get("parent_id")
    if pid and ChatMessage.query.get(int(pid)):
        m.parent_id = int(pid)
    peer = data.get("peer_id")
    group = data.get("group_id")
    if peer:
        u = User.query.get(int(peer))
        if not u:
            return jsonify({"error": "no such user"}), 400
        m.peer_id = u.id
    elif group:
        g = ChatGroup.query.get_or_404(int(group))
        if current_user.id not in (g.member_ids or []):
            if current_user.id in (g.left_ids or []):
                return jsonify({"error": "you're no longer a member of this group"}), 403
            return jsonify({"error": "not a member of this group"}), 403
        m.group_id = g.id
    else:
        return jsonify({"error": "peer_id or group_id required"}), 400
    db.session.add(m)
    db.session.commit()
    return jsonify({"ok": True, "message": {**m.to_dict(), "sender": current_user.username}}), 201


@api.post("/chat/groups")
@login_required
def chat_create_group():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()[:80]
    members = [int(x) for x in (data.get("member_ids") or [])]
    if not name or not members:
        return jsonify({"error": "group name and members are required"}), 400
    # JOIN ORDER matters (admin hand-over goes to the longest-standing member):
    # creator first, then the picked members in the order they were given
    ids = [current_user.id]
    for m in members:
        if m not in ids and User.query.get(m):
            ids.append(m)
    g = ChatGroup(name=name, member_ids=ids, left_ids=[], created_by=current_user.id)
    db.session.add(g)
    db.session.flush()
    _sys_msg(g.id, '%s created the group "%s"' % (current_user.username, name))
    # every added member gets an in-app notification (pops out of Buddy)
    for uid in ids:
        if uid != current_user.id:
            _notify(uid, "chat_group", g.id,
                    '%s added you to the group "%s"' % (current_user.username, name))
    db.session.commit()
    return jsonify({"ok": True, "group": g.to_dict()}), 201


@api.post("/chat/upload")
@login_required
def chat_upload():
    """Store an attachment (image / file) for chat or a ticket discussion."""
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "no file"}), 400
    from werkzeug.utils import secure_filename
    name = secure_filename(f.filename)[:200] or "file"
    os.makedirs(_CHAT_UPLOAD_DIR, exist_ok=True)
    stored = "%d_%s_%s" % (current_user.id, datetime.utcnow().strftime("%Y%m%d%H%M%S%f"), name)
    full = os.path.join(_CHAT_UPLOAD_DIR, stored)
    f.save(full)
    return jsonify({"ok": True, "file_name": name, "file_path": stored})


@api.get("/chat/file/<path:stored>")
@login_required
def chat_file(stored):
    """Serve an uploaded attachment (signed-in users only)."""
    from flask import send_from_directory
    safe = os.path.basename(stored)
    return send_from_directory(os.path.abspath(_CHAT_UPLOAD_DIR), safe)


@api.post("/cases/<int:tid>/events")
@login_required
def attach_case_events(tid):
    """Manually attach events to a ticket (e.g. something the chain grouping
    missed but the analyst judges to be part of the same attack)."""
    t = Ticket.query.get_or_404(tid)
    ids = request.get_json(force=True).get("event_ids") or []
    have = {e.id for e in t.events}
    added = []
    excl = list(t.excluded_event_ids or [])
    for eid in ids:
        e = Event.query.get(int(eid))
        if e and e.id not in have:
            t.events.append(e)
            have.add(e.id)
            added.append(e.id)
            # an explicit re-attach clears any earlier detach exclusion
            if e.id in excl:
                excl.remove(e.id)
    if not added:
        return jsonify({"error": "no new valid event ids"}), 400
    t.excluded_event_ids = excl
    _tk_act(t, "Events attached manually: %s" % ", ".join("#%d" % i for i in added),
            current_user.id)
    _audit("ticket_updated", "attached events %s to ticket T-%d"
           % (", ".join("#%d" % i for i in added), t.id))
    db.session.commit()
    unames = {u.id: u.username for u in User.query.all()}
    return jsonify({"ok": True, "attached": added, "ticket": _tk_json(t, unames, deep=True)})


@api.delete("/cases/<int:tid>/events/<int:eid>")
@login_required
def detach_case_event(tid, eid):
    """Undo a wrong manual attach: unlink one event from the ticket."""
    t = Ticket.query.get_or_404(tid)
    e = next((x for x in t.events if x.id == eid), None)
    if e is None:
        return jsonify({"error": "event #%d is not attached to this ticket" % eid}), 404
    t.events.remove(e)
    # remember the detach so "re-run AI analysis" doesn't silently re-add it
    excl = list(t.excluded_event_ids or [])
    if eid not in excl:
        excl.append(eid)
        t.excluded_event_ids = excl
    _tk_act(t, "Event #%d detached" % eid, current_user.id)
    _audit("ticket_updated", "detached event #%d from ticket T-%d" % (eid, t.id))
    db.session.commit()
    unames = {u.id: u.username for u in User.query.all()}
    return jsonify({"ok": True, "ticket": _tk_json(t, unames, deep=True)})


# ---- keep the case in step with the event verdict -----------------------
def _fw_change_needed(t, reason):
    """'block' / 'unblock' when closing with this reason would touch the
    firewall, else None. Used to refuse such a close for an account without
    the Firewall Blocks permission, instead of closing with the gap left open."""
    if not t.source_ip:
        return None
    blocked = BlockedIP.query.filter_by(ip=t.source_ip, active=True).first() is not None
    if reason == "True positive" and not blocked:
        return "block"
    if reason == "False positive" and blocked:
        return "unblock"
    return None


def _close_effects(t, reason):
    """Follow-through of a verdict given by closing a ticket.

    False positive: every event still waiting for a decision is dismissed (fed
    back to the classifier as a false positive), the chains are recomputed, and
    a blocked source is unblocked. True positive: the source is blocked if it is
    not already, and the waiting events are marked blocked. The firewall part
    needs the Firewall Blocks permission; without it the ticket still closes
    and the trail says the firewall was not touched. Returns activity lines."""
    lines = []
    if reason not in ("False positive", "True positive"):
        return lines
    from app.agents.response import response_agent
    can_fw = current_user.has_cap("block_ips")
    ip = t.source_ip
    blk = BlockedIP.query.filter_by(ip=ip, active=True).first() if ip else None
    if reason == "False positive":
        n = 0
        chains = set()
        for e in t.events:
            if e.status == "awaiting":
                e.status = "dismissed"
                e.suppress_reason = "false_positive"
                db.session.add(Decision(event_id=e.id, user_id=current_user.id,
                                        action="dismissed", label="false_positive"))
                n += 1
                if e.chain_id:
                    chains.add(e.chain_id)
        for cid in chains:
            _recompute_chain(cid)
        if n:
            lines.append("%d waiting event(s) dismissed as false positives" % n)
        if blk:
            if can_fw:
                response_agent.unblock_ip(ip)
                blk.active = False
                _audit_block("ip_unblocked", ip, "ticket T-%d closed as a false positive" % t.id)
                lines.append("%s unblocked" % ip)
            else:   # not reachable through the API (refused earlier); kept for safety
                lines.append("%s left blocked: unblock not permitted for this account" % ip)
    else:  # True positive
        if ip and not blk:
            if can_fw:
                response_agent.block_ip(ip)
                db.session.add(BlockedIP(ip=ip, attack_type="ticket T-%d closed as a true positive" % t.id,
                                         blocked_by="analyst"))
                _audit_block("ip_blocked", ip, "ticket T-%d closed as a true positive" % t.id)
                lines.append("%s blocked" % ip)
                blk = True
            else:   # not reachable through the API (refused earlier); kept for safety
                lines.append("%s not blocked: block not permitted for this account" % ip)
        if blk:
            n = 0
            for e in t.events:
                if e.status == "awaiting":
                    e.status = "blocked"
                    e.fp_prev_status = None
                    e.suppress_reason = None
                    db.session.add(Decision(event_id=e.id, user_id=current_user.id,
                                            action="approved", label="true_positive"))
                    n += 1
            if n:
                lines.append("%d waiting event(s) confirmed as real attacks" % n)
    return lines


def _recompute_chain(chain_id):
    """Rebuild a chain's stages, risk and next stage from its events that are
    NOT dismissed, so a false-positive mark (or its undo) shows on the chain at
    once instead of waiting for the attacker's next event. Uses the same maths
    and the same 180-day window as the correlation agent. A chain whose events
    are all dismissed keeps its row (tickets still point at it) with no stages
    and no risk."""
    if not chain_id:
        return
    from datetime import timedelta as _td
    from app.agents.correlation import compute_chain, CORRELATION_WINDOW_DAYS
    chain = AttackChain.query.get(chain_id)
    if chain is None:
        return
    since = datetime.utcnow() - _td(days=CORRELATION_WINDOW_DAYS)
    live = [ev for ev in Event.query.filter_by(chain_id=chain.id).all()
            if ev.status != "dismissed" and (ev.last_seen is None or ev.last_seen >= since)]
    c = compute_chain([{"attack_type": ev.attack_type,
                        "timestamp": ev.last_seen.isoformat() if ev.last_seen else "",
                        "risk": ev.risk} for ev in live])
    chain.stages = c["chain_stages"]
    chain.stage_count = len(c["chain_stages"])
    chain.highest_risk = c["chain_risk"]
    chain.predicted_next = c["predicted_next"]


_AUTO_CLOSE_NOTE = "Closed automatically: every event in this case was marked as a false positive."


def _sync_ticket_after_verdict(e, action):
    """Called after an event is dismissed (false positive) or reopened (undo).
    Every ticket holding the event gets an activity line naming the analyst.
    If a dismissal leaves NO event in the case that is not a false positive, the
    case is closed automatically (reason False positive, note above, activity by
    CyREN); an undo on such an auto-closed case reopens it. Cases closed by a
    person are never reopened here."""
    for t in Ticket.query.filter(Ticket.events.any(Event.id == e.id)).all():
        if action == "dismissed":
            _tk_act(t, "Event #%d marked as a false positive" % e.id, current_user.id)
            if t.status != "closed" and t.events and all(x.status == "dismissed" for x in t.events):
                # the analyst who marked the last event is the closer of record;
                # the note (checked on undo) is what makes this an automatic close
                t.status = "closed"
                t.closed_at = datetime.utcnow()
                t.closed_by = current_user.id
                t.close_reason = "False positive"
                t.close_note = _AUTO_CLOSE_NOTE
                _tk_act(t, "Closed — False positive\n" + _AUTO_CLOSE_NOTE
                        + " (last mark by %s on event #%d)" % (current_user.username, e.id), current_user.id)
                _audit("ticket_closed",
                       "closed ticket T-%d automatically after %s marked every event as a false positive"
                       % (t.id, current_user.username))
        elif action == "reopen":
            _tk_act(t, "Event #%d is no longer a false positive, back to %s"
                    % (e.id, (e.status or "").replace("_", " ")), current_user.id)
            if t.status == "closed" and t.close_note == _AUTO_CLOSE_NOTE:
                t.status = "assigned" if t.assignee_id else "queue"
                t.closed_at = None
                t.closed_by = None
                t.close_reason = None
                t.close_note = None
                _tk_act(t, "Reopened automatically: event #%d is no longer a false positive" % e.id)
                _audit("ticket_status", "reopened ticket T-%d automatically" % t.id)


@api.post("/events/<int:event_id>/decision")
@login_required
def decide(event_id):
    deny = _require_cap("approve_events")
    if deny:
        return deny
    e = Event.query.get_or_404(event_id)
    data = request.get_json(force=True)
    action = data.get("action")   # "approved" | "dismissed"

    if action == "approved":
        from app.agents.response import response_agent
        # approving blocks the address, so unless it is blocked already this
        # needs the Firewall Blocks permission (same rule as closing a case as
        # a true positive); Dismiss stays a Tickets-permission decision
        if (e.source_ip and not BlockedIP.query.filter_by(ip=e.source_ip, active=True).first()
                and not current_user.has_cap("block_ips")):
            return jsonify({"error": "approving this event would block %s, which needs the "
                                     "Firewall Blocks permission" % e.source_ip}), 403
        # don't stack duplicate active rows for one IP: several events from the
        # same attacker (SQLi + XSS + brute) would otherwise each add a row, and
        # unblocking one would leave the IP shown as blocked while the firewall
        # no longer drops it
        if not BlockedIP.query.filter_by(ip=e.source_ip, active=True).first():
            response_agent.block_ip(e.source_ip)
            db.session.add(BlockedIP(ip=e.source_ip, attack_type=e.attack_type,
                                     blocked_by="analyst", event_id=e.id))
            # record it in the incident-response audit trail so the event/case
            # "Response History" and the PDF response log show who blocked it
            _audit_block("ip_blocked", e.source_ip,
                         reason=f"analyst approved event #{e.id} "
                                f"({e.attack_type or 'threat'})")
        e.status = "blocked"
        # "It's a real attack" override: clear any false-positive marks so the
        # feedback flips to true positive and a later Undo won't restore a stale state.
        e.fp_prev_status = None
        e.suppress_reason = None
        label = "true_positive"
    elif action == "dismissed":
        # False positive: label THIS one event and feed the model. No time-based
        # suppression any more -- identical repeats are downgraded/folded by the
        # pipeline instead, and a different payload still alerts normally. The
        # firewall is NOT touched (use the unblock endpoint for that).
        note = (data.get("note") or "").strip()[:200]
        note_sfx = (" — %s" % note) if note else ""
        # optional, from the Event Detail dialog: lift the firewall block in the
        # same step. Needs the block_ips permission, like the unblock endpoint.
        if data.get("unblock"):
            deny = _require_cap("block_ips")
            if deny:
                return deny
            blk = BlockedIP.query.filter_by(ip=e.source_ip, active=True).first()
            if blk:
                from app.agents.response import response_agent
                response_agent.unblock_ip(blk.ip)
                blk.active = False
                _audit_block("ip_unblocked", blk.ip,
                             f"unblocked with the false positive on event #{e.id}")
        if not e.fp_prev_status:
            e.fp_prev_status = e.status        # remember original state for Undo
        e.status = "dismissed"
        label = "false_positive"
        e.suppressed_until = None
        e.suppress_reason = "false_positive"
        _audit("event_dismissed",
               "event #%d %s from %s marked as a false positive%s"
               % (e.id, e.attack_type or "event", e.source_ip or "?", note_sfx))
    elif action == "reopen":
        # Undo / not-a-false-positive: restore the event's ORIGINAL state
        # (blocked / awaiting / logged), not a fixed one, and clear the FP mark
        # so the classifier feedback is reverted too. Recorded so it is not silent.
        if e.status != "dismissed":
            return jsonify({"error": "only a dismissed event can be reopened"}), 400
        # optional, from the Event Detail dialog: put the firewall block back in
        # the same step (re-activate the old row, or create one if none exists)
        if data.get("reblock"):
            deny = _require_cap("block_ips")
            if deny:
                return deny
            if not BlockedIP.query.filter_by(ip=e.source_ip, active=True).first():
                from app.agents.response import response_agent
                response_agent.block_ip(e.source_ip)
                prev = (BlockedIP.query.filter_by(ip=e.source_ip)
                        .order_by(BlockedIP.id.desc()).first())
                if prev:
                    prev.active = True
                    _audit_block("ip_reblocked", e.source_ip,
                                 f"re-blocked with the undo on event #{e.id}")
                else:
                    db.session.add(BlockedIP(ip=e.source_ip, attack_type=e.attack_type,
                                             blocked_by="analyst", event_id=e.id))
                    _audit_block("ip_blocked", e.source_ip,
                                 f"re-blocked with the undo on event #{e.id}")
        e.status = e.fp_prev_status or "awaiting"
        e.fp_prev_status = None
        e.suppressed_until = None
        e.suppress_reason = None
        label = "reopened"
        _audit("event_reopened",
               "event #%d %s from %s false positive undone, returned to %s"
               % (e.id, e.attack_type or "event", e.source_ip or "?", e.status))
    elif action == "suppress_extend":
        if e.status != "dismissed":
            return jsonify({"error": "only a dismissed event can be suppressed"}), 400
        try:
            days = int(data.get("suppress_days") or 0)
        except (TypeError, ValueError):
            days = 0
        if days <= 0:
            return jsonify({"error": "a keep period in days is required"}), 400
        e.suppressed_until = datetime.utcnow() + timedelta(days=days)
        e.suppress_notified = False
        label = "suppress_extended"
        _audit("event_reopened",
               "event #%d %s from %s suppression extended to %s"
               % (e.id, e.attack_type or "event", e.source_ip or "?",
                  e.suppressed_until.date().isoformat()))
    elif action == "suppress_end":
        if e.status != "dismissed":
            return jsonify({"error": "only a dismissed event can be un-suppressed"}), 400
        e.suppressed_until = None
        label = "suppress_ended"
        _audit("event_reopened",
               "event #%d %s from %s suppression ended, repeats will alert again"
               % (e.id, e.attack_type or "event", e.source_ip or "?"))
    else:
        return jsonify({"error": "invalid action"}), 400

    if action in ("dismissed", "reopen"):
        _sync_ticket_after_verdict(e, action)
        _recompute_chain(e.chain_id)
    db.session.add(Decision(event_id=e.id, user_id=current_user.id,
                            action=action, label=label))
    db.session.commit()
    return jsonify({"ok": True, "event": e.to_dict()})


# --------------------------------------------------------------------- chains
@api.get("/chains")
@login_required
def list_chains():
    tk_by_chain = {t.chain_id: t.id
                   for t in Ticket.query.filter(Ticket.chain_id.isnot(None)).all()}
    # every ticket that holds one of the chain's events (a chain can span several
    # tickets: a closed case plus the new one opened by a later burst)
    tk_by_event = {}
    for t in Ticket.query.all():
        for ev in t.events:
            tk_by_event.setdefault(ev.id, set()).add(t.id)
    out = []
    for c in AttackChain.query.all():
        d = c.to_dict()
        d["ticket_id"] = tk_by_chain.get(c.id)
        d["event_ids"] = [e.id for e in (c.events or [])]
        tids = set()
        for e in (c.events or []):
            tids |= tk_by_event.get(e.id, set())
        if d["ticket_id"]:
            tids.add(d["ticket_id"])
        d["ticket_ids"] = sorted(tids)
        out.append(d)
    return jsonify(out)


@api.get("/chains/<int:chain_id>")
@login_required
def chain_detail(chain_id):
    c = AttackChain.query.get_or_404(chain_id)
    d = c.to_dict()
    # every event behind the chain (a stage repeats across bursts, so one stage
    # can hold several events) + the tickets holding them + the target asset
    tk_by_event = {}
    for t in Ticket.query.all():
        for ev in t.events:
            tk_by_event.setdefault(ev.id, t.id)
    evs = sorted(c.events or [], key=lambda x: (x.first_seen or x.ingested_at or datetime.min))
    d["events"] = [{"id": x.id, "attack_type": x.attack_type, "risk": x.risk, "status": x.status,
                    "log_count": x.log_count, "confidence": x.confidence,
                    "mitre_techniques": x.mitre_techniques or [],
                    "first_seen": x.first_seen.isoformat() if x.first_seen else None,
                    "last_seen": x.last_seen.isoformat() if x.last_seen else None,
                    "ticket_id": tk_by_event.get(x.id)} for x in evs]
    tids = {tk_by_event[x.id] for x in evs if x.id in tk_by_event}
    for t in Ticket.query.filter_by(chain_id=c.id).all():
        tids.add(t.id)
    d["ticket_ids"] = sorted(tids)
    tgt = next((x for x in reversed(evs) if x.asset_info or x.dest_ip), None)
    d["target"] = ({"name": (tgt.asset_info or {}).get("name"), "ip": (tgt.asset_info or {}).get("ip") or tgt.dest_ip,
                    "criticality": (tgt.asset_info or {}).get("criticality")} if tgt else None)
    return jsonify(d)


@api.get("/chains/<int:chain_id>/predict")
@login_required
def get_chain_prediction(chain_id):
    """Return the cached LLM deep-prediction for a chain, if one exists."""
    row = db.session.get(ChainPrediction, chain_id)
    return jsonify(row.to_dict() if row else {"prediction": None})


@api.post("/chains/<int:chain_id>/predict")
@login_required
def make_chain_prediction(chain_id):
    """Generate an LLM deep-prediction for the chain's next step (on demand,
    when the user clicks the button). The rule-based predicted_next is untouched.
    Stages are enriched with the real MITRE techniques from the source IP's
    events before the LLM sees them."""
    chain = AttackChain.query.get_or_404(chain_id)
    c = chain.to_dict()
    by_type = {}
    for e in Event.query.filter_by(source_ip=chain.source_ip).all():
        by_type.setdefault(e.attack_type, e)
    for s in c.get("stages", []):
        ev = by_type.get(s.get("attack_type"))
        if ev and ev.mitre_techniques:
            s["mitre"] = ev.mitre_techniques

    from app.agents.investigation import _investigation
    pred = _investigation.predict_next_stage(c)
    if not pred.get("available"):
        return jsonify({"ok": False, "error": pred.get("error", "LLM unavailable")}), 503

    row = db.session.get(ChainPrediction, chain_id)
    if row is None:
        row = ChainPrediction(chain_id=chain_id)
        db.session.add(row)
    row.prediction = pred
    row.created_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "prediction": pred,
                    "created_at": row.created_at.isoformat()})


@api.get("/chains/<int:chain_id>/report/download")
@login_required
def download_chain_report(chain_id):
    """A single PDF for the whole attack chain: summary, kill-chain timeline
    (stages joined to their real events), both predictions, and every related event."""
    from app.services.report_service import generate_chain_report
    chain = AttackChain.query.get_or_404(chain_id)
    by_type = {}
    for e in Event.query.filter_by(source_ip=chain.source_ip).all():
        by_type.setdefault(e.attack_type, e)
    stages = []
    for s in (chain.stages or []):
        ev = by_type.get(s.get("attack_type"))
        stages.append({**s,
                       "mitre": (ev.mitre_techniques if ev else None) or [],
                       "log_count": ev.log_count if ev else None,
                       "risk": ev.risk if ev else None})
    ip_events = Event.query.filter_by(source_ip=chain.source_ip).all()
    events = [e.to_dict() for e in ip_events]        # Related Events summary: always all
    # per-event DETAIL pages are selectable: when the `events` param is present,
    # include EXACTLY those events -- an empty list gives a chain-overview-only
    # report (no detail pages). Param absent (a direct link) -> all detail pages.
    detail_events = ip_events
    if "events" in request.args:
        want = {int(x) for x in (request.args.get("events") or "").split(",") if x.strip().isdigit()}
        detail_events = [e for e in ip_events if e.id in want]
    event_details = [_state_from_event(e) for e in detail_events]
    pred_row = db.session.get(ChainPrediction, chain_id)
    sc = chain.stage_count or len(chain.stages or [])
    assessment = ("Multiple kill-chain phases observed from this source, indicating a "
                  "sustained, targeted attack." if sc >= 3
                  else "Two kill-chain phases observed from this source." if sc == 2
                  else "Single-phase activity from this source.")
    risk_map = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "uncertain"}
    state = {
        "report_title": "Attack Chain Report",
        "report_ref": f"Chain #C-{chain.id}",
        "source_ip": chain.source_ip,
        "risk": risk_map.get((chain.highest_risk or "").upper(), "uncertain"),
        "chain_risk": chain.highest_risk,
        "chain_assessment": assessment,
        "stage_count": sc,
        "first_seen": chain.first_seen.isoformat() if chain.first_seen else None,
        "last_seen": chain.last_seen.isoformat() if chain.last_seen else None,
        "stages": stages,
        "events": events,
        "event_details": event_details,
        "predicted_next": chain.predicted_next,
        "ai_prediction": (pred_row.prediction if pred_row else None),
    }
    path = generate_chain_report({**state, "generated_by": current_user.username})
    if not os.path.isabs(path):
        path = os.path.join(_PROJECT_ROOT, path)
    # inline by default so it opens in a browser tab to view; ?download=1 saves it
    return send_file(path, as_attachment=bool(request.args.get("download")),
                     download_name=os.path.basename(path))


# -------------------------------------------------------------------- blocked
@api.get("/blocked")
@login_required
def list_blocked():
    return jsonify([b.to_dict() for b in BlockedIP.query.order_by(BlockedIP.created_at.desc()).all()])


@api.get("/blocked/ips")
@login_required
def blocked_ips():
    """The Firewall Blocks list, ONE row per source IP: current state, the
    active block's id (for the Unblock button), how many block episodes, and a
    quick event summary. The per-IP detail (events, history, ticket, chain) is
    loaded on demand from /blocked/ip/<ip> when a row is expanded."""
    blocks = BlockedIP.query.order_by(BlockedIP.created_at.desc()).all()
    by_ip = {}
    for b in blocks:
        d = by_ip.setdefault(b.ip, {"ip": b.ip, "active": False, "episodes": 0,
                                    "active_block_id": None, "last_block_id": None,
                                    "last_at": None})
        d["episodes"] += 1
        if d["last_at"] is None:
            d["last_at"] = b.created_at.isoformat() if b.created_at else None
            d["last_block_id"] = b.id
        if b.active and not d["active"]:
            d["active"] = True
            d["active_block_id"] = b.id
    wl = {w.ip: w for w in Whitelist.query.all()}
    for ip, w in wl.items():
        by_ip.setdefault(ip, {"ip": ip, "active": False, "episodes": 0,
                              "active_block_id": None, "last_block_id": None,
                              "last_at": w.created_at.isoformat() if w.created_at else None})
    for ip, d in by_ip.items():
        d["whitelisted"] = ip in wl
        if ip in wl and wl[ip].created_at:
            # the state date of a whitelisted row is when it was whitelisted
            d["last_at"] = wl[ip].created_at.isoformat()
    ips = list(by_ip.keys())
    ev_by_ip = {}
    if ips:
        for e in Event.query.filter(Event.source_ip.in_(ips)).all():
            ev_by_ip.setdefault(e.source_ip, []).append(e)
    # events -> tickets, so a search for an event #, ticket T-x or chain #C-x
    # surfaces the IP row that holds it
    tk_by_event = {}
    for t in Ticket.query.all():
        for e in t.events:
            tk_by_event.setdefault(e.id, set()).add(t.id)
    for ip, d in by_ip.items():
        lst = ev_by_ip.get(ip, [])
        types = sorted({e.attack_type for e in lst if e.attack_type})
        d["n_events"] = len(lst)
        d["n_types"] = len(types)
        d["n_awaiting"] = sum(1 for e in lst if e.status == "awaiting")
        d["top_type"] = types[0] if types else None
        tids, cids = set(), set()
        for e in lst:
            tids |= tk_by_event.get(e.id, set())
            if e.chain_id:
                cids.add(e.chain_id)
        # everything this row can be found by (lower-cased, space-joined)
        parts = [ip] + types + ["#%d" % e.id for e in lst] + \
                ["t-%d" % t for t in tids] + ["#c-%d" % c for c in cids]
        d["search"] = " ".join(parts).lower()
    out = sorted(by_ip.values(), key=lambda d: (not d["active"], d["whitelisted"], -(d["n_events"] or 0), d["last_at"] or ""))
    return jsonify(out)


@api.get("/blocked/ip/<ip>")
@login_required
def blocked_ip_detail(ip):
    """One IP's expanded firewall detail: its block/unblock history, the events
    it covers (with each event's disposition, so dismissed ones can grey out),
    and the tickets and attack chains those events belong to."""
    unames = {u.id: u.username for u in User.query.all()}
    # the real block/unblock/re-block timeline for this IP, so each row says
    # WHAT happened, WHEN and by WHO (clearer than "block episode" rows)
    history = _response_log(ip)
    active_now = ip in _blocked_ip_set()
    evs = (Event.query.filter_by(source_ip=ip)
           .order_by(Event.first_seen).all())
    tk_by_event = {}
    for t in Ticket.query.all():
        for e in t.events:
            tk_by_event.setdefault(e.id, t.id)
    events = [{"id": e.id, "attack_type": e.attack_type, "status": e.status,
               "suppressed_until": e.suppressed_until.isoformat() if e.suppressed_until else None,
               "ticket_id": tk_by_event.get(e.id)} for e in evs]
    tids, cids = set(), set()
    for e in evs:
        if e.id in tk_by_event:
            tids.add(tk_by_event[e.id])
        if e.chain_id:
            cids.add(e.chain_id)
    for t in Ticket.query.filter_by(source_ip=ip).all():
        tids.add(t.id)
    w = Whitelist.query.filter_by(ip=ip).first()
    wl_info = None
    if w:
        wl_info = w.to_dict()
        u = User.query.get(w.added_by) if w.added_by else None
        wl_info["by"] = u.username if u else None
    return jsonify({"ip": ip, "active": active_now, "history": history, "events": events,
                    "tickets": sorted(tids), "chains": sorted(cids), "whitelist": wl_info})


def _blocked_ip_set():
    """The set of source IPs currently blocked at the firewall. This is the
    single source of truth for the live 'source blocked' indicator, kept
    SEPARATE from an event's own triage disposition (awaiting/dismissed/...)."""
    return {b.ip for b in BlockedIP.query.filter_by(active=True).all()}


def _audit_block(action, ip, reason=""):
    """Record a block/unblock action for the incident-response audit trail:
    who did it, to which IP, why, and (via created_at) when."""
    detail = f"'{ip}'" + (f" - reason: {reason}" if reason else "")
    db.session.add(AuditLog(user_id=getattr(current_user, "id", None),
                            action=action, detail=detail))


def _audit(action, detail):
    """Generic audit entry attributed to the current user (who + action + when).
    Used for user-management and asset changes so a manager can see who did what."""
    db.session.add(AuditLog(user_id=getattr(current_user, "id", None),
                            action=action, detail=detail))


@api.post("/blocked")
@login_required
def add_block():
    """Manually block an IP (the "Add Block" button on Firewall Blocks)."""
    deny = _require_cap("block_ips")
    if deny:
        return deny
    data = request.get_json(force=True)
    ip = (data.get("ip") or "").strip()
    reason = (data.get("reason") or "").strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) or any(int(o) > 255 for o in ip.split(".")):
        return jsonify({"error": "invalid IPv4 address"}), 400
    if BlockedIP.query.filter_by(ip=ip, active=True).first():
        return jsonify({"error": "IP is already blocked"}), 409
    from app.agents.response import response_agent
    response_agent.block_ip(ip)
    b = BlockedIP(ip=ip, attack_type=reason or "Manual block", blocked_by="analyst")
    db.session.add(b)
    # NOTE: firewall block is separate from an event's triage disposition, so we
    # do NOT rewrite event statuses here. The live 'source_blocked' flag reflects
    # the block; each event keeps its own awaiting/dismissed/blocked disposition.
    _audit_block("ip_blocked", ip, reason)
    db.session.commit()
    return jsonify({"ok": True, "block": b.to_dict()}), 201


@api.post("/blocked/<int:block_id>/unblock")
@login_required
def unblock(block_id):
    deny = _require_cap("block_ips")
    if deny:
        return deny
    from app.agents.response import response_agent
    b = BlockedIP.query.get_or_404(block_id)
    reason = (request.get_json(silent=True) or {}).get("reason", "").strip()
    removed = response_agent.unblock_ip(b.ip)
    b.active = False
    _audit_block("ip_unblocked", b.ip, reason)   # event dispositions untouched
    db.session.commit()
    return jsonify({"ok": True, "iptables_removed": removed})


# ------------------------------------------------------------------ whitelist
@api.get("/whitelist")
@login_required
def list_whitelist():
    """Trusted sources: who added them, why, and how many events they raised since."""
    unames = {u.id: u.username for u in User.query.all()}
    out = []
    for w in Whitelist.query.order_by(Whitelist.created_at.desc()).all():
        d = w.to_dict()
        d["by"] = unames.get(w.added_by)
        # "still active after being trusted": repeats of the same attack fold
        # into the existing event (only last_seen moves), so count by last_seen
        q = Event.query.filter(Event.source_ip == w.ip)
        if w.created_at:
            q = q.filter(Event.last_seen >= w.created_at)
        d["events_since"] = q.count()
        out.append(d)
    return jsonify(out)


_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _valid_ipv4(ip):
    return bool(_IPV4.match(ip or "")) and all(int(o) <= 255 for o in ip.split("."))


@api.get("/whitelist/known")
@login_required
def whitelist_known():
    """Every address CyREN knows (event sources, block list, asset inventory),
    for the address picker in the Add to whitelist dialog."""
    from app.enrichment.asset_assessment import Asset
    ips = {r[0] for r in db.session.query(Event.source_ip).distinct() if r[0]}
    ips |= {b.ip for b in BlockedIP.query.with_entities(BlockedIP.ip).all() if b.ip}
    ips |= {a.ip for a in Asset.query.with_entities(Asset.ip).all() if a.ip}
    # numeric order (…56.1, 56.2, …56.10), not string order (…56.1, 56.10, 56.100)
    return jsonify(sorted((i for i in ips if _valid_ipv4(i)),
                          key=lambda i: tuple(int(o) for o in i.split("."))))


@api.get("/whitelist/check")
@login_required
def whitelist_check():
    """What CyREN knows about an address the analyst is about to trust, so a
    typo is caught before it is saved: events seen, last seen, blocked now,
    inventory asset, already on the list, or excluded as CyREN's own address."""
    from app.enrichment.asset_assessment import Asset
    from app.services.siem_service import _is_blacklisted
    ip = (request.args.get("ip") or "").strip()
    out = {"ip": ip, "valid": _valid_ipv4(ip)}
    if not out["valid"]:
        return jsonify(out)
    out["blacklisted"] = _is_blacklisted(ip)
    out["on_whitelist"] = Whitelist.query.filter_by(ip=ip).first() is not None
    out["blocked"] = BlockedIP.query.filter_by(ip=ip, active=True).first() is not None
    out["events"] = Event.query.filter_by(source_ip=ip).count()
    last = Event.query.filter_by(source_ip=ip).with_entities(db.func.max(Event.last_seen)).scalar()
    out["last_seen"] = last.isoformat() if last else None
    a = Asset.query.filter_by(ip=ip).first()
    out["asset"] = {"name": a.name, "criticality": a.criticality} if a else None
    out["known"] = bool(out["events"] or out["blocked"] or a)
    return jsonify(out)


@api.post("/whitelist")
@login_required
def add_whitelist():
    """Whitelist an address (needs the Block IPs permission). Any active block
    on it is lifted at the same time, and both steps land in the audit trail."""
    deny = _require_cap("block_ips")
    if deny:
        return deny
    data = request.get_json(force=True) or {}
    ip = (data.get("ip") or "").strip()
    reason = (data.get("reason") or "").strip()[:200]
    if not _valid_ipv4(ip):
        return jsonify({"error": "invalid IPv4 address"}), 400
    from app.services.siem_service import _is_blacklisted
    if _is_blacklisted(ip):
        return jsonify({"error": "this address is excluded from detection (SOURCE_IP_BLACKLIST), "
                                 "so there is nothing to whitelist"}), 400
    if not reason:
        return jsonify({"error": "a reason is required"}), 400
    if Whitelist.query.filter_by(ip=ip).first():
        return jsonify({"error": "this address is already on the whitelist"}), 409
    w = Whitelist(ip=ip, reason=reason, added_by=current_user.id)
    db.session.add(w)
    _audit_block("ip_whitelisted", ip, reason)
    lifted = False
    for b in BlockedIP.query.filter_by(ip=ip, active=True).all():
        from app.agents.response import response_agent
        response_agent.unblock_ip(b.ip)
        b.active = False
        lifted = True
    if lifted:
        _audit_block("ip_unblocked", ip, "block lifted when the address was whitelisted")
    db.session.commit()
    return jsonify({"ok": True, "whitelist": w.to_dict(), "block_lifted": lifted}), 201


@api.delete("/whitelist/<int:wid>")
@login_required
def remove_whitelist(wid):
    """Take an address off the whitelist: CyREN treats it like any other source again."""
    deny = _require_cap("block_ips")
    if deny:
        return deny
    w = Whitelist.query.get_or_404(wid)
    ip = w.ip
    db.session.delete(w)
    _audit_block("ip_unwhitelisted", ip, "removed from the whitelist")
    db.session.commit()
    return jsonify({"ok": True, "ip": ip})


@api.post("/blocked/<int:block_id>/reblock")
@login_required
def reblock(block_id):
    """Re-apply a previously unblocked entry: mark it active again so the
    blocklist feed serves the IP and the target re-blocks it on the next sync."""
    deny = _require_cap("block_ips")
    if deny:
        return deny
    from app.agents.response import response_agent
    b = BlockedIP.query.get_or_404(block_id)
    reason = (request.get_json(silent=True) or {}).get("reason", "").strip()
    b.active = True
    applied = response_agent.block_ip(b.ip)
    _audit_block("ip_reblocked", b.ip, reason)   # event dispositions untouched
    db.session.commit()
    return jsonify({"ok": True, "iptables_applied": applied})


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


def _state_from_event(e):
    """Rebuild the pipeline-state dict the report writer expects from a
    persisted Event, so any event can be turned into a PDF on demand."""
    chain = AttackChain.query.get(e.chain_id) if e.chain_id else None
    # the block may belong to an EARLIER event of the same attacker IP (dedup
    # never stacks a second BlockedIP row), so fall back to the active block for
    # this source IP — else the PDF says action_taken=blocked but blocked=false
    block = (BlockedIP.query.filter_by(event_id=e.id).first()
             or BlockedIP.query.filter_by(ip=e.source_ip, active=True).first())

    decision = (Decision.query.filter_by(event_id=e.id)
                .order_by(Decision.id.desc()).first())
    decided_by = decided_at = None
    if decision:
        user = User.query.get(decision.user_id) if decision.user_id else None
        decided_by = user.full_name or user.username if user else "unknown analyst"
        decided_at = decision.created_at.isoformat() if decision.created_at else None

    response_log = _response_log(e.source_ip)

    # the event stores only a 20-line sample; for the report, pull the FULL set
    # of real log lines for this source in the event's window from ES so the
    # "Raw Log Sample" section is complete (falls back to the stored sample)
    full_logs = list(e.raw_log_sample or [])
    if e.first_seen and e.source_ip:
        try:
            from app.services.siem_service import siem_service
            from datetime import timedelta as _td
            want = min(int(e.log_count or len(full_logs) or 0) or 500, 500)
            rows, _tot = siem_service.search_raw_logs(
                source_ip=e.source_ip, start=e.first_seen,
                end=(e.last_seen or e.first_seen) + _td(minutes=1),
                page=1, per=max(want, len(full_logs)), order="asc")
            if rows:
                full_logs = [r.get("message") or "" for r in rows]
        except Exception:
            pass   # ES unavailable — keep the stored sample

    stage_count = (chain.stage_count or len(chain.stages or [])) if chain else 0
    if chain:
        assessment = (
            "Multiple kill chain phases observed from this source, indicating a "
            "sustained and deliberate attack." if stage_count >= 3 else
            "Two kill chain phases observed from this source." if stage_count == 2 else
            "Single-phase activity. Limited attack scope observed."
        )
    else:
        assessment = None

    return {
        "event_id": e.id,
        "source_ip": e.source_ip, "dest_ip": e.dest_ip,
        "attack_type": e.attack_type, "rule": e.rule,
        "log_count": e.log_count, "risk": e.risk,
        "confidence": e.confidence, "severity": e.risk,
        "first_seen": e.first_seen.isoformat() if e.first_seen else None,
        "last_seen": e.last_seen.isoformat() if e.last_seen else None,
        "mitre_techniques": e.mitre_techniques or [],
        "llm_summary": e.llm_summary or {},
        "raw_log_sample": full_logs,
        "threat_intel": e.threat_intel or {},
        "asset": e.asset_info or {},
        "vulnerability": e.vuln_info or {},
        "is_multistage": stage_count > 1,
        "chain_id": e.chain_id,
        "chain_risk": chain.highest_risk if chain else None,
        "chain_assessment": assessment,
        "chain_stages": (chain.stages or []) if chain else [],
        "predicted_next": chain.predicted_next if chain else None,
        "action_taken": ("whitelisted" if e.suppress_reason == "whitelist" else
                         {"blocked": "blocked", "awaiting": "awaiting_approval",
                          "dismissed": "dismissed as false positive",
                          "unblocked": "block lifted by analyst"}.get(e.status, "logged")),
        "blocked": bool(block and block.active),
        "blocked_at": block.created_at.isoformat() if block and block.created_at else None,
        "blocked_by": block.blocked_by if block else None,
        "decided_by": decided_by,
        "decided_at": decided_at,
        "decision_action": decision.action if decision else None,
        "response_log": response_log,
        "ticket": _ticket_for_event(e),
        "notes": _people_rows(EventNote.query.filter_by(event_id=e.id)
                              .order_by(EventNote.created_at).all(),
                              {u.id: u.username for u in User.query.all()}),
    }


def _people_rows(items, unames):
    """Ticket comments / event notes -> plain dicts for the PDF, with the
    edited and deleted markers the web page shows (a deleted entry keeps its
    place as a tombstone, its text is not printed)."""
    out = []
    for c in items:
        text, by = (c.text or ""), (unames.get(c.user_id) or "unknown")
        if text.startswith("[[AI]]"):          # a note posted by the CyREN assistant
            text, by = text[6:].lstrip(), "CyREN (AI)"
        out.append({"created_at": c.created_at.isoformat() if c.created_at else None,
                    "by": by,
                    "text": text,
                    "edited": bool(c.edited_at),
                    "deleted_by": unames.get(c.deleted_by) if c.deleted_at else None})
    return out


def _ticket_for_event(e):
    """The case ticket this event belongs to (for the PDF's Ticket section)."""
    row = db.session.execute(db.text("SELECT ticket_id FROM ticket_events WHERE event_id = :i"),
                             {"i": e.id}).fetchone()
    t = Ticket.query.get(row[0]) if row else None
    if not t:
        return None
    unames = {u.id: u.username for u in User.query.all()}
    return {"id": t.id, "title": t.title, "status": t.status,
            "owner": unames.get(t.assignee_id) or "unassigned",
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "description": t.description,
            "close_reason": t.close_reason, "close_note": t.close_note,
            "closed_by": unames.get(t.closed_by),
            "closed_at": t.closed_at.isoformat() if t.closed_at else None,
            "comments": _people_rows(TicketComment.query.filter_by(ticket_id=t.id)
                                     .order_by(TicketComment.created_at).all(), unames)}


def _ensure_report(event):
    """Return this event's report, regenerating it when missing or outdated.

    A report is reused only if the file is still on disk *and* was produced by
    the current report format; otherwise it is rebuilt, so a redesign of the
    PDF reaches events that were reported on by an earlier version.
    """
    from app.services.report_service import generate_report, REPORT_FORMAT_VERSION

    rep = (Report.query.filter_by(event_id=event.id)
           .order_by(Report.id.desc()).first())
    if rep:
        existing = _report_path(rep)
        if existing and f"_{REPORT_FORMAT_VERSION}." in os.path.basename(existing):
            return rep

    path = generate_report({**_state_from_event(event), "generated_by": current_user.username})
    resolution = {"blocked": "auto_blocked", "awaiting": "awaiting_approval",
                  "dismissed": "dismissed"}.get(event.status, "logged")
    if rep:
        rep.file_path = path
        rep.resolution = resolution
    else:
        rep = Report(event_id=event.id,
                     title=f"{event.attack_type or 'Event'} from {event.source_ip}",
                     risk=event.risk, resolution=resolution, file_path=path)
        db.session.add(rep)
    db.session.commit()
    return rep


@api.post("/events/<int:event_id>/report")
@login_required
def create_event_report(event_id):
    """Generate (or reuse) the PDF incident report for any event."""
    e = Event.query.get_or_404(event_id)
    return jsonify({"ok": True, "report": _ensure_report(e).to_dict()})


@api.get("/events/<int:event_id>/report/download")
@login_required
def download_event_report(event_id):
    e = Event.query.get_or_404(event_id)
    rep = _ensure_report(e)
    path = _report_path(rep)
    if not path:
        return jsonify({"error": "report could not be generated"}), 500
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@api.get("/events/<int:event_id>/report/preview")
@login_required
def preview_event_report(event_id):
    e = Event.query.get_or_404(event_id)
    rep = _ensure_report(e)
    path = _report_path(rep)
    if not path:
        return jsonify({"error": "report could not be generated"}), 500
    return send_file(path)


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


def _zip_pdfs(pairs):
    """Bundle (path, arcname) PDF pairs into an in-memory zip for one download."""
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path, arcname in pairs:
            if path and os.path.exists(path):
                z.write(path, arcname=arcname)
    buf.seek(0)
    return buf


def _ids_arg():
    return [int(x) for x in request.args.get("ids", "").split(",") if x.strip().isdigit()]


@api.get("/events/report-zip")
@login_required
def events_report_zip():
    """Bulk download: a single zip of the PDF incident reports for the given events."""
    ids = _ids_arg()
    if not ids:
        return jsonify({"error": "no event ids"}), 400
    pairs = []
    for eid in ids:
        e = Event.query.get(eid)
        if not e:
            continue
        p = _report_path(_ensure_report(e))
        if p:
            pairs.append((p, os.path.basename(p)))
    return send_file(_zip_pdfs(pairs), mimetype="application/zip",
                     as_attachment=True, download_name="cyren_event_reports.zip")


@api.get("/reports/zip")
@login_required
def reports_zip():
    """Bulk download: a single zip of the selected incident report PDFs."""
    ids = _ids_arg()
    if not ids:
        return jsonify({"error": "no report ids"}), 400
    pairs = []
    for rid in ids:
        r = Report.query.get(rid)
        if not r:
            continue
        p = _report_path(r)
        if p:
            pairs.append((p, os.path.basename(p)))
    return send_file(_zip_pdfs(pairs), mimetype="application/zip",
                     as_attachment=True, download_name="cyren_reports.zip")


@api.post("/reports/<int:report_id>/delete")
@login_required
def delete_report(report_id):
    """Delete an incident report (row and its PDF file). The event is untouched;
    a fresh report can be regenerated on demand."""
    r = Report.query.get_or_404(report_id)
    path = _report_path(r)
    if path and os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass
    db.session.delete(r)
    db.session.commit()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------- users
@api.get("/users")
@login_required
def list_users():
    # Any signed-in user may VIEW the team roster (username, role, status, email)
    # so colleagues can find each other. Creating / editing / deleting still needs
    # 'manage_users' (enforced on those endpoints).
    return jsonify([u.to_dict() for u in User.query.all()])


@api.post("/users")
@login_required
def create_user():
    """Add User (needs 'manage_users'). The SYSTEM generates a strong one-time
    password and returns it once; the new user is forced to change it on first
    login (User.must_change_password). The manager never chooses the password."""
    deny = _require_cap("manage_users")
    if deny:
        return deny
    from app.api.auth import _generate_temp_password, _valid_email
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    # Name and username are unified: the account is identified by its username,
    # which also serves as the display name (full_name mirrors it).
    full_name = username
    # role is a free-text job title / label (Tier-1, IR Lead, ...); authority
    # comes from the permission checkboxes below, not from this name
    role = (data.get("role") or "").strip()[:48]
    if not role:
        return jsonify({"error": "a job title is required"}), 400
    if not username:
        return jsonify({"error": "username is required"}), 400
    # usernames are unique IGNORING capitalisation: "Chong" vs "chong" would be
    # two accounts that look identical everywhere (chat, assignments, audit)
    if User.query.filter(db.func.lower(User.username) == username.lower()).first():
        return jsonify({"error": "username already taken (capitalisation does not make it different)"}), 409
    email = (data.get("email") or "").strip()
    if not email:
        return jsonify({"error": "an email is required. The one-time password is sent there"}), 400
    if not _valid_email(email):
        return jsonify({"error": "please enter a valid email address"}), 400
    if User.email_taken(email):
        return jsonify({"error": "that email is already used by another account"}), 409
    temp_password = _generate_temp_password()
    u = User(username=username, full_name=full_name, email=email, role=role,
             must_change_password=True)
    u.set_password(temp_password)
    # Per-account permissions straight from the Add-User form: capability boxes
    # plus the read-page sub-toggles. If the form sent no view_pages, fall back
    # to the standard pre-tick (all read pages EXCEPT Audit Logs) so a new
    # account never silently gains audit access.
    raw_perms = data.get("permissions")
    if not isinstance(raw_perms, dict):
        raw_perms = {}
    for _k, _v in DEFAULT_NEW_CAPS.items():
        raw_perms.setdefault(_k, _v)
    raw_perms.setdefault("view_pages", dict(DEFAULT_VIEW_PAGES))
    u.permissions = _clean_overrides(raw_perms) or None
    db.session.add(u)
    db.session.flush()
    _audit("user_created", f"'{username}' as {role}")
    db.session.commit()
    # The one-time password is emailed DIRECTLY to the new user and is never
    # shown to the manager, so a compromised manager account cannot learn (and
    # impersonate with) an employee's password. It is never stored in plaintext.
    sent = _email_temp_password(u, temp_password, first=True)
    return jsonify({"ok": True, "user": u.to_dict(), "emailed_to": email, "email_sent": sent}), 201


def _email_temp_password(user, temp_password, first=False, lead=None):
    """Email a one-time password straight to the account owner. Returns True if an
    SMTP server accepted it, False if email is not configured (then the code is
    written to the server log, mirroring the password-reset flow)."""
    from app.services.email_service import send_alert_email
    lead = lead or ("An account has been created for you on CyREN."
                    if first else "Your CyREN password has been reset by a manager.")
    html = (
        "<div style=\"font-family:Arial,sans-serif;max-width:520px;margin:auto\">"
        "<h2 style=\"color:#0d2c50\">CyREN one-time password</h2>"
        f"<p>{lead} Your username is <b>{user.username}</b>.</p>"
        "<p>Sign in with this one-time password:</p>"
        f"<p style=\"font-size:26px;font-weight:800;letter-spacing:3px;color:#0d2c50\">{temp_password}</p>"
        "<p>You will be asked to set your own password immediately. If you did not "
        "expect this, contact your SOC manager.</p></div>")
    return send_alert_email(to=user.email,
                            subject="[CyREN] Your one-time password", html_body=html)


@api.patch("/users/<int:user_id>")
@login_required
def update_user(user_id):
    """Edit a user. Needs 'manage_users' for name/enable/disable. Changing the
    ROLE or the per-user capability overrides is a privilege-granting action and
    stays strictly manager-only, so an analyst who is given 'manage_users' still
    cannot promote anyone (including themselves) or hand out capabilities."""
    deny = _require_cap("manage_users")
    if deny:
        return deny
    u = User.query.get_or_404(user_id)
    data = request.get_json(force=True)
    changes = []
    pending_request = None   # new address waiting for the owner's confirmation
    if "full_name" in data:
        name = (data.get("full_name") or "").strip()
        if not name:
            return jsonify({"error": "full name cannot be empty"}), 400
        if name != u.full_name:
            changes.append("renamed")
        u.full_name = name
    if "email" in data:
        from app.api.auth import _valid_email
        email = (data.get("email") or "").strip()
        if not email:
            return jsonify({"error": "an email is required; the one-time password is sent there"}), 400
        if not _valid_email(email):
            return jsonify({"error": "please enter a valid email address"}), 400
        if User.email_taken(email, exclude_id=u.id):
            return jsonify({"error": "that email is already used by another account"}), 409
        if email != (u.email or ""):
            if not u.email:
                # every account has an address (required at creation and at
                # registration); a legacy one without it cannot be asked
                return jsonify({"error": "this account has no email address on record, so the owner cannot be asked to confirm; the owner can set one in My Profile"}), 400
            # the change waits for the owner's confirmation from the current mailbox
            pending_request = email
    if "role" in data:
        # role is now a free-text job title / label — it grants no authority, so
        # it only needs this endpoint's manage_users capability and never touches
        # anyone's permissions.
        title = (data.get("role") or "").strip()[:48]
        if not title:
            return jsonify({"error": "job title cannot be empty"}), 400
        if title != u.role:
            changes.append(f"title -> {title}")
        u.role = title
    if "permissions" in data:
        overrides = _clean_overrides(data.get("permissions"))
        # LAST-ADMIN SAFEGUARD: never let an edit leave the system with nobody
        # able to manage users. If this would drop u's 'manage_users' and no
        # OTHER active account still has it, force it back on (covers an admin
        # editing themselves as well as demoting another admin).
        new_manage_users = (overrides or {}).get(
            "manage_users", BASE_DEFAULTS["manage_users"])
        if u.has_cap("manage_users") and not new_manage_users \
                and not has_other_admin(u.id):
            overrides = dict(overrides or {})
            overrides["manage_users"] = True
            overrides = _clean_overrides(overrides)
            changes.append("kept last administrator's user management")
        if (overrides or None) != (u.permissions or None):
            changes.append("permissions changed")
        u.permissions = overrides
    if "is_active" in data:
        if u.id == current_user.id and not data["is_active"]:
            return jsonify({"error": "you cannot disable your own account"}), 400
        if not data["is_active"] and u.has_cap("manage_users") and not has_other_admin(u.id):
            return jsonify({"error": "cannot disable the last administrator"}), 400
        if bool(data["is_active"]) != bool(u.is_active):
            changes.append("enabled" if data["is_active"] else "disabled")
        u.is_active = bool(data["is_active"])
    email_sent = None
    if pending_request:
        u.pending_email = pending_request
        u.pending_email_by = current_user.id
        u.pending_email_expires = datetime.utcnow() + timedelta(minutes=EMAIL_CHANGE_TTL_MIN)
        changes.append("email change requested (awaiting the owner's confirmation)")
    if changes:
        _audit("user_updated", f"'{u.username}': {', '.join(changes)}")
    db.session.commit()
    if pending_request:
        # SMTP (STARTTLS + login) takes seconds: build the message here, hand it
        # to a background thread, and answer the manager straight away
        email_sent = _email_change_request(u)
    out = {"ok": True, "user": u.to_dict()}
    if pending_request:
        out["email_pending"] = True
        out["email_sent"] = bool(email_sent)   # True = handed to the mail thread
    return jsonify(out)


# how long the owner has to answer a manager's email-change request
EMAIL_CHANGE_TTL_MIN = 10


def _email_change_token(user):
    """Signed token for the confirm / reject links. It carries the user id and
    the requested address, so a link can only act on the request it was made
    for; the server also checks the request is still pending and unexpired."""
    from itsdangerous import URLSafeTimedSerializer
    from flask import current_app
    ser = URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="email-change")
    return ser.dumps({"uid": user.id, "new": user.pending_email})


def _email_change_request(user):
    """Ask the account owner, at the CURRENT mailbox, to confirm or reject the
    change a manager just requested. The message deliberately names nothing:
    no addresses, no username, no manager. A stolen mailbox must not learn a
    CyREN login name from it (a password reset needs username + email)."""
    from app.services.email_service import send_alert_email
    from config.settings import settings
    tok = _email_change_token(user)
    base = settings.APP_BASE_URL.rstrip("/")
    ok_url = f"{base}/email-change/{tok}/confirm"
    no_url = f"{base}/email-change/{tok}/reject"
    btn = "display:inline-block;padding:10px 22px;border-radius:6px;font-weight:700;text-decoration:none;margin:0 8px"
    html = (
        "<div style=\"font-family:Arial,sans-serif;max-width:520px;margin:auto\">"
        "<h2 style=\"color:#0d2c50\">Confirm a change to your CyREN account</h2>"
        "<p>A change to the email address on your CyREN account has been "
        "requested.</p>"
        "<p>If this is expected, confirm it. A one-time password will then be sent "
        "to the new address and you will sign in with it and set a new password.</p>"
        f"<p style=\"text-align:center;margin:22px 0\"><a href=\"{ok_url}\" style=\"{btn};background:#0b8fa5;color:#fff\">Confirm</a>"
        f"<a href=\"{no_url}\" style=\"{btn};background:#c0392b;color:#fff\">Not me</a></p>"
        f"<p style=\"color:#555\">These links are valid for {EMAIL_CHANGE_TTL_MIN} minutes. "
        "If you do nothing, your account stays exactly as it is.</p></div>")
    if not settings.SMTP_HOST:
        # nothing can be sent; log the would-be message as the mail service does
        send_alert_email(to=user.email,
                         subject="[CyREN] Confirm the change to your account email",
                         html_body=html)
        return False
    import threading
    to = user.email
    threading.Thread(
        target=lambda: send_alert_email(
            to=to, subject="[CyREN] Confirm the change to your account email", html_body=html),
        daemon=True, name="cyren-email-change").start()
    return True


def _clean_overrides(raw):
    """Normalise a permissions payload into stored overrides: keep only known
    capabilities that DIFFER from the base default, coerced to booleans, plus an
    optional per-read-page 'view_pages' map. Returns None when empty (the account
    then runs on the base capabilities and sees every read page)."""
    if not isinstance(raw, dict):
        return None
    out = {}
    for k in CAPABILITY_KEYS:
        if k in raw:
            val = bool(raw[k])
            if val != BASE_DEFAULTS.get(k, False):
                out[k] = val
    # Per-read-page visibility (the sub-toggles under 'view'). Only meaningful
    # when the user can view at all, and only worth storing when it actually
    # turns a page OFF (all-on is the back-compat default, so it stays implicit).
    view_on = out.get("view", BASE_DEFAULTS["view"])
    vp_raw = raw.get("view_pages")
    if view_on and isinstance(vp_raw, dict):
        vp = {k: bool(vp_raw.get(k, True)) for k in VIEW_PAGE_KEYS}
        if not all(vp.values()):
            out["view_pages"] = vp
    return out or None


@api.delete("/users/<int:user_id>")
@login_required
def delete_user(user_id):
    """Manager-only: permanently delete a user account.

    Guards mirror update_user: a manager cannot delete their own account, and
    the last remaining manager cannot be deleted (the system must always keep at
    least one manager who can administer it). To retire the sole manager, first
    promote another user to manager in User Management, then delete the old one.

    The affected user is force-logged-out on their next request: load_user()
    returns None once the row is gone, so they are bounced to the sign-in page.
    """
    deny = _require_cap("manage_users")
    if deny:
        return deny
    u = User.query.get_or_404(user_id)
    if u.id == current_user.id:
        return jsonify({"error": "you cannot delete your own account"}), 400
    if u.has_cap("manage_users") and not has_other_admin(u.id):
        return jsonify({"error": "cannot delete the last administrator"}), 400
    username = u.username
    # Detach the user from their historical decisions/audit rows rather than
    # cascading a delete, so the incident history stays intact (the rows simply
    # lose their analyst attribution).
    for d in Decision.query.filter_by(user_id=u.id).all():
        d.user_id = None
    db.session.delete(u)
    _audit("user_deleted", f"'{username}'")
    db.session.commit()
    return jsonify({"ok": True, "deleted": username})


@api.post("/users/<int:user_id>/approve")
@login_required
def approve_user(user_id):
    """Approve a SELF-REGISTERED pending account (needs 'manage_users'). The
    manager sets the job title and ticks the capabilities to grant; the account
    is then activated and can sign in. Rejecting a request is just a normal
    delete of the pending account (DELETE /users/<id>)."""
    deny = _require_cap("manage_users")
    if deny:
        return deny
    u = User.query.get_or_404(user_id)
    if not u.pending_approval:
        return jsonify({"error": "this account is not pending approval"}), 400
    data = request.get_json(force=True)
    role = (data.get("role") or "").strip()[:48]
    if not role:
        return jsonify({"error": "a job title is required"}), 400
    raw_perms = data.get("permissions")
    if not isinstance(raw_perms, dict):
        raw_perms = {}
    for _k, _v in DEFAULT_NEW_CAPS.items():
        raw_perms.setdefault(_k, _v)
    raw_perms.setdefault("view_pages", dict(DEFAULT_VIEW_PAGES))
    overrides = _clean_overrides(raw_perms)
    u.role = role
    u.permissions = overrides
    u.pending_approval = False
    u.is_active = True
    granted = [k for k in CAPABILITY_KEYS if u.has_cap(k)]
    _audit("user_approved", f"'{u.username}' approved as {role}; caps={granted}")
    db.session.commit()
    return jsonify({"ok": True, "user": u.to_dict()})


# ------------------------------------------------------------------ settings
# AI automation policy: how much the Response agent may do without a human.
#   advisory  - never auto-contain; every high/uncertain event -> Human Approval
#   standard  - auto-block high risk; uncertain -> Human Approval  (default)
#   full_auto - auto-block high AND uncertain risk
AUTOMATION_LEVELS = ("advisory", "standard", "full_auto")


def _automation_level():
    """Current level, falling back to the legacy auto_block_enabled boolean."""
    lvl = Setting.get("automation_level")
    if lvl in AUTOMATION_LEVELS:
        return lvl
    return "standard" if Setting.get_bool("auto_block_enabled", True) else "advisory"


@api.get("/settings")
@login_required
def get_settings():
    """Operational settings the UI shows. Readable by any signed-in user."""
    from config.settings import settings
    hi = Setting.get("high_risk_threshold")
    lo = Setting.get("low_risk_threshold")
    return jsonify({
        "automation_level": _automation_level(),
        "auto_block_enabled": Setting.get_bool("auto_block_enabled", True),
        # thresholds as percentages for the UI; live value from DB or .env default
        "high_risk_threshold": round(float(hi if hi is not None else settings.HIGH_RISK_THRESHOLD) * 100),
        "low_risk_threshold": round(float(lo if lo is not None else settings.LOW_RISK_THRESHOLD) * 100),
    })


@api.post("/settings/thresholds")
@login_required
def set_thresholds():
    """Change the risk thresholds. Needs 'change_thresholds'; persisted (so the
    Triage agent routes on the new values) and audited."""
    deny = _require_cap("change_thresholds")
    if deny:
        return deny
    data = request.get_json(force=True)
    try:
        hi = int(data.get("high"))
        lo = int(data.get("low"))
    except (TypeError, ValueError):
        return jsonify({"error": "high and low must be whole percentages"}), 400
    if not (0 <= lo < hi <= 100):
        return jsonify({"error": "need 0 <= LOW < HIGH <= 100"}), 400

    from config.settings import settings
    prev_hi = Setting.get("high_risk_threshold")
    prev_lo = Setting.get("low_risk_threshold")
    prev_hi = round(float(prev_hi if prev_hi is not None else settings.HIGH_RISK_THRESHOLD) * 100)
    prev_lo = round(float(prev_lo if prev_lo is not None else settings.LOW_RISK_THRESHOLD) * 100)

    for key, val in (("high_risk_threshold", hi / 100.0), ("low_risk_threshold", lo / 100.0)):
        row = db.session.get(Setting, key)
        if row is None:
            row = Setting(key=key)
            db.session.add(row)
        row.value = str(val)
        row.updated_by = current_user.id
    # Re-bucket EXISTING events so risk reflects the new policy (only the risk
    # label moves; decisions/status/timestamps/blocks are untouched, so MTTR and
    # the response history are unaffected).
    rescored = _rescore_events(hi / 100.0, lo / 100.0)
    contained = _contain_after_rescore("threshold change")
    if (prev_hi, prev_lo) != (hi, lo) or contained:
        # an unchanged save that still contained something is worth a line too
        db.session.add(AuditLog(
            user_id=current_user.id, action="thresholds_changed",
            detail=f"HIGH {prev_hi}->{hi}, LOW {prev_lo}->{lo}"
                   f" ({rescored} event(s) re-scored"
                   + (f", {contained} auto-contained" if contained else "") + ")"))
    db.session.commit()
    return jsonify({"ok": True, "high_risk_threshold": hi, "low_risk_threshold": lo,
                    "rescored": rescored, "contained": contained})


def _rescore_events(hi, lo):
    """Recompute every event's stored risk LABEL from its fixed confidence and the
    given thresholds (fractions 0-1), re-applying asset criticality exactly as
    triage does. Returns how many events changed tier. Decisions, timestamps and
    existing blocks are untouched; the one follow-through is done separately by
    _contain_after_rescore (an awaiting event that is now HIGH is contained)."""
    from app.enrichment.asset_assessment import asset_assessment
    order = ["low", "uncertain", "high"]
    changed = 0
    raised = []
    for e in Event.query.all():
        c = e.confidence
        if c is None:
            continue
        base = "high" if c >= hi else ("low" if c <= lo else "uncertain")
        idx = order.index(base)
        try:
            # criticality bump comes from the TARGET asset (dest), exactly as
            # triage applied it — using source_ip here silently dropped the
            # tier for events that hit a critical asset from an unknown source
            idx += asset_assessment.criticality_bump(e.dest_ip)
        except Exception:
            pass
        new_risk = order[max(0, min(len(order) - 1, idx))]
        if new_risk == "high" and e.status == "awaiting":
            # rated high under the policy now in force but never contained
            # (raised by this re-score, by an earlier one, or by a level change)
            raised.append(e)
        if new_risk != e.risk:
            e.risk = new_risk
            changed += 1
    _rescore_events.raised = raised   # read by _contain_after_rescore
    return changed


def _contain_after_rescore(why):
    """Policy follow-through for a re-score: an event that the new thresholds or
    the new asset criticality now rate HIGH, and that is still waiting for a
    decision, is handled the way it would have been had it arrived as high
    under the current automation level. At 'standard' or 'full_auto' its
    source is blocked now (one active row per address, never twice); at
    'advisory' it stays in Human Approval. Whitelisted sources are skipped.
    Returns how many events were contained."""
    raised = getattr(_rescore_events, "raised", []) or []
    _rescore_events.raised = []
    if not raised:
        return 0
    from app.agents.response import response_agent
    level = _automation_level()
    if level not in ("standard", "full_auto"):
        return 0
    done = 0
    for e in raised:
        if not e.source_ip or Whitelist.query.filter_by(ip=e.source_ip).first():
            continue
        if not BlockedIP.query.filter_by(ip=e.source_ip, active=True).first():
            response_agent.block_ip(e.source_ip)
            db.session.add(BlockedIP(ip=e.source_ip, attack_type=e.attack_type,
                                     blocked_by="auto", event_id=e.id))
            _audit_block("ip_blocked", e.source_ip,
                         reason=f"auto-contained after {why} ({e.attack_type or 'threat'}, event #{e.id})")
        else:
            # the address is already dropped at the firewall: only the event's
            # status catches up, but say so in the trail
            _audit("event_contained",
                   f"event #{e.id} ({e.attack_type or 'threat'}) from {e.source_ip} marked blocked after {why}, "
                   f"source already blocked")
        e.status = "blocked"
        done += 1
    return done


@api.post("/settings/auto-block")
@login_required
def set_auto_block():
    """Toggle auto-block. Needs 'change_thresholds'; persisted and audited."""
    deny = _require_cap("change_thresholds")
    if deny:
        return deny
    data = request.get_json(force=True)
    enabled = bool(data.get("enabled"))
    prev = Setting.get_bool("auto_block_enabled", True)
    row = db.session.get(Setting, "auto_block_enabled")
    if row is None:
        row = Setting(key="auto_block_enabled")
        db.session.add(row)
    row.value = "1" if enabled else "0"
    row.updated_by = current_user.id
    if prev != enabled:
        db.session.add(AuditLog(
            user_id=current_user.id, action="auto_block_changed",
            detail=f"Auto-block {'ON' if prev else 'OFF'} -> {'ON' if enabled else 'OFF'}"))
    db.session.commit()
    return jsonify({"ok": True, "auto_block_enabled": enabled})


@api.post("/settings/automation-level")
@login_required
def set_automation_level():
    """Set the AI automation policy (4 levels). Needs 'change_thresholds';
    persisted so the Response agent acts on the new level immediately, and audited."""
    deny = _require_cap("change_thresholds")
    if deny:
        return deny
    data = request.get_json(force=True)
    level = (data.get("level") or "").strip()
    if level not in AUTOMATION_LEVELS:
        return jsonify({"error": "invalid automation level"}), 400
    prev = _automation_level()
    row = db.session.get(Setting, "automation_level")
    if row is None:
        row = Setting(key="automation_level")
        db.session.add(row)
    row.value = level
    row.updated_by = current_user.id
    # keep the legacy boolean consistent for anything still reading it
    b = db.session.get(Setting, "auto_block_enabled")
    if b is None:
        b = Setting(key="auto_block_enabled")
        db.session.add(b)
    b.value = "1" if level in ("standard", "full_auto") else "0"
    if prev != level:
        db.session.add(AuditLog(
            user_id=current_user.id, action="automation_level_changed",
            detail=f"Automation level {prev} -> {level}"))
    db.session.commit()
    return jsonify({"ok": True, "automation_level": level})


# the readable Action labels of the Audit Log page (mirrors AUDIT_ACTIONS in
# index.html) so a search for the words on screen finds the coded rows
AUDIT_LABELS = {
    "ip_blocked": "Blocked IP", "ip_unblocked": "Unblocked IP", "ip_reblocked": "Re-blocked IP",
    "ip_whitelisted": "Whitelisted IP", "ip_unwhitelisted": "Unwhitelisted IP",
    "event_escalated": "Escalated to event", "event_contained": "Contained event",
    "event_dismissed": "Dismissed event", "event_reopened": "Reopened event",
    "ticket_created": "Created ticket", "ticket_updated": "Updated ticket", "ticket_assigned": "Assigned ticket",
    "ticket_status": "Ticket status changed", "ticket_closed": "Closed ticket", "ticket_deleted": "Deleted ticket",
    "thresholds_changed": "Changed risk thresholds", "auto_block_changed": "Changed auto-block",
    "automation_level_changed": "Changed automation level", "retrain_schedule_changed": "Changed auto-retrain", "retrain_cancelled": "Cancelled retraining",
    "retrain_started": "Started retraining", "retrain_finished": "Finished retraining", "retrain_failed": "Retraining failed",
    "user_created": "Created user", "user_updated": "Updated user", "user_deleted": "Deleted user",
    "user_approved": "Approved user", "user_selfregistered": "User self-registered",
    "email_change_rejected": "Email change rejected", "email_change_confirmed": "Email change confirmed",
    "profile_updated": "Updated profile", "password_reset": "Password reset",
    "password_reset_failed": "Password reset failed", "user_password_reset": "Reset user password",
    "asset_created": "Created asset", "asset_updated": "Updated asset", "asset_deleted": "Deleted asset",
    "report_generated": "Generated report", "report_note_added": "Added report comment",
    "report_note_edited": "Edited report comment", "report_note_deleted": "Deleted report comment",
}


@api.get("/audit")
@login_required
def get_audit():
    """One page of audit-log entries, filtered and paged in SQL so the whole
    trail stays searchable however long it grows. Readable by every analyst
    (transparency); only user management itself stays manager-gated. Login
    events (both OK and failed) are NOT shown here -- they live in
    My Profile > Login History.

    Query string: page (1-based), per (<= 100), q (free text over the detail,
    the action and the actor's username), action (comma-separated action codes),
    day (YYYY-MM-DD, in the browser's local time), time (HH:MM, entries at or
    after that time of day) and tz (the browser's offset from UTC in minutes,
    added to the stored UTC timestamps before the day / time comparison).
    Returns {rows, total, page, per, actions} where actions is the distinct
    list of recorded action codes for the dropdown and the column funnel."""
    args = request.args
    try:
        page = max(1, int(args.get("page", 1) or 1))
    except ValueError:
        page = 1
    try:
        per = min(100, max(1, int(args.get("per", 10) or 10)))
    except ValueError:
        per = 10
    try:
        tz = int(args.get("tz", 0) or 0)
    except ValueError:
        tz = 0
    q = (args.get("q") or "").strip()
    actions = [a for a in (args.get("action") or "").split(",") if a]
    day = (args.get("day") or "").strip()
    tm = (args.get("time") or "").strip()[:5]

    hidden = ["login_failed", "login_success"]
    action_list = sorted(x[0] for x in db.session.query(AuditLog.action)
                         .filter(AuditLog.action.notin_(hidden)).distinct().all() if x[0])
    qry = (AuditLog.query.outerjoin(User, User.id == AuditLog.user_id)
           .filter(AuditLog.action.notin_(hidden)))
    if q:
        like = "%" + q + "%"
        # the action matches when every word typed appears in the label the
        # page shows ("blocked ip" -> ip_blocked) or in the code itself
        words = q.lower().split()

        def _label_hit(a):
            lw = (AUDIT_LABELS.get(a, "") + " " + a.replace("_", " ")).lower().split()
            return all(any(x.startswith(w) for x in lw) for w in words)
        by_label = [a for a in action_list if _label_hit(a)]
        qry = qry.filter(or_(AuditLog.detail.ilike(like),
                             User.username.ilike(like),
                             AuditLog.action.in_(by_label) if by_label else False))
    if actions:
        qry = qry.filter(AuditLog.action.in_(actions))
    if day or tm:
        local = func.datetime(AuditLog.created_at, "%+d minutes" % tz)
        if day:
            qry = qry.filter(func.date(local) == day)
        if tm:
            qry = qry.filter(func.strftime("%H:%M", local) >= tm)
    total = qry.count()
    rows = qry.order_by(AuditLog.id.desc()).offset((page - 1) * per).limit(per).all()
    users = {u.id: u.username for u in User.query.all()}
    out = []
    for a in rows:
        d = a.to_dict()
        d["username"] = users.get(a.user_id)
        out.append(d)
    return jsonify({"rows": out, "total": total, "page": page, "per": per, "actions": action_list})


@api.get("/me/logins")
@login_required
def my_logins():
    """The signed-in user's own login history: EVERY recorded successful
    sign-in and every failed attempt on their account, newest first."""
    out = []
    oks = (AuditLog.query.filter_by(action="login_success", user_id=current_user.id)
           .order_by(AuditLog.id.desc()).limit(100).all())
    for s in oks:
        out.append({"time": s.created_at.isoformat() if s.created_at else None,
                    "ok": True, "detail": "Successful sign-in"})
    # legacy fallback: sign-ins from before per-login records existed only
    # stamped last_login on the user row — show it whenever it is newer than
    # anything recorded, so the latest login is never missing from the list
    newest = oks[0].created_at if oks else None
    if current_user.last_login and (newest is None or
                                    current_user.last_login > newest + timedelta(minutes=1)):
        out.append({"time": current_user.last_login.isoformat(),
                    "ok": True, "detail": "Successful sign-in"})
    fails = (AuditLog.query.filter_by(action="login_failed", user_id=current_user.id)
             .order_by(AuditLog.id.desc()).limit(100).all())
    for f in fails:
        # strip the leading quoted username; the reason is what matters here
        reason = (f.detail or "").split(" - ", 1)[-1] if f.detail else "failed attempt"
        out.append({"time": f.created_at.isoformat() if f.created_at else None,
                    "ok": False, "detail": "Failed sign-in (" + reason + ")"})
    # self-service password resets (via forgot-password) belong in the account's
    # own auth history too
    resets = (AuditLog.query.filter_by(action="password_reset", user_id=current_user.id)
              .order_by(AuditLog.id.desc()).limit(50).all())
    for rr in resets:
        out.append({"time": rr.created_at.isoformat() if rr.created_at else None,
                    "ok": True, "info": True, "detail": "Password reset"})
    # lockouts (account temporarily locked after too many failed attempts)
    locks = (AuditLog.query.filter_by(action="login_locked", user_id=current_user.id)
             .order_by(AuditLog.id.desc()).limit(50).all())
    for lk in locks:
        out.append({"time": lk.created_at.isoformat() if lk.created_at else None,
                    "ok": False, "lock": True,
                    "detail": "Account locked (too many failed attempts)"})
    # denied password-reset requests (wrong username/email on this account)
    rfails = (AuditLog.query.filter_by(action="password_reset_failed", user_id=current_user.id)
              .order_by(AuditLog.id.desc()).limit(50).all())
    for rf in rfails:
        out.append({"time": rf.created_at.isoformat() if rf.created_at else None,
                    "ok": False, "detail": "Denied password-reset request (username/email mismatch)"})
    # manager-requested email changes answered by this account's owner: a
    # rejection is a security signal for the account, a confirmation changed
    # where its password resets go (and issued a one-time password)
    rejs = (AuditLog.query.filter_by(action="email_change_rejected", user_id=current_user.id)
            .order_by(AuditLog.id.desc()).limit(50).all())
    for rj in rejs:
        out.append({"time": rj.created_at.isoformat() if rj.created_at else None,
                    "ok": False, "rej": True,
                    "detail": "Email change request rejected (not made by you)"})
    confs = (AuditLog.query.filter_by(action="email_change_confirmed", user_id=current_user.id)
             .order_by(AuditLog.id.desc()).limit(50).all())
    for cf in confs:
        out.append({"time": cf.created_at.isoformat() if cf.created_at else None,
                    "ok": True, "mail": True,
                    "detail": "Email address changed (confirmed by you); one-time password issued"})
    out.sort(key=lambda x: x["time"] or "", reverse=True)
    return jsonify(out)


# ----------------------------------------------------------------- raw logs
@api.get("/raw-logs")
@login_required
def raw_logs():
    """Live, read-only window into the raw Elasticsearch logs (nothing copied
    into CyREN's DB). Filters: ?q=&ip=&from=&to=&page=&per=. Each row is tagged
    with the event it was aggregated into, if any (so the UI can jump there)."""
    from app.services.siem_service import siem_service
    start, end, err = _parse_date_range()
    if err:
        return jsonify({"error": err}), 400
    try:
        page = max(1, int(request.args.get("page", 1)))
        per = min(100, max(1, int(request.args.get("per", 50))))
    except (TypeError, ValueError):
        page, per = 1, 50
    if page * per > 10000:
        # Elasticsearch's from+size window — tell the truth instead of erroring
        return jsonify({"error": "Elasticsearch can only page through the first "
                                 "10,000 results — narrow the filters instead",
                        "available": True, "rows": [], "total": 0,
                        "page": page, "per": per}), 200
    order = request.args.get("order") or "desc"
    rows, total = siem_service.search_raw_logs(
        q=(request.args.get("q") or "").strip() or None,
        source_ip=(request.args.get("ip") or "").strip() or None,
        start=start, end=end, page=page, per=per, order=order)
    if rows is None:
        return jsonify({"error": "Elasticsearch is unavailable", "available": False,
                        "rows": [], "total": 0, "page": page, "per": per}), 200
    # tag each log with the event that covers its source IP AND its moment in
    # time (an event is one aggregation window) — logs outside any window get
    # no badge, so the same IP can map to different events on different days
    ips = {r["source_ip"] for r in rows if r.get("source_ip")}
    ev_by_ip = {}
    if ips:
        for e in Event.query.filter(Event.source_ip.in_(list(ips))).all():
            ev_by_ip.setdefault(e.source_ip, []).append(e)

    def _log_event(r):
        cands = ev_by_ip.get(r.get("source_ip")) or []
        try:
            tsd = datetime.fromisoformat(
                str(r.get("timestamp") or "").replace("Z", "").split("+")[0][:19])
        except (TypeError, ValueError):
            tsd = None
        best = None
        for e in cands:
            if tsd is None or not e.first_seen or not e.last_seen:
                continue
            if (e.first_seen - timedelta(minutes=10) <= tsd
                    <= e.last_seen + timedelta(minutes=10)):
                if best is None or (e.last_seen - e.first_seen) < (best.last_seen - best.first_seen):
                    best = e
        return best.id if best else None

    for r in rows:
        r["event_id"] = _log_event(r)
    # freshness signal: the newest log timestamp in the whole index, so the UI
    # can warn when log shipping (Filebeat) has stopped and the store is stale
    latest = None
    try:
        latest = siem_service.latest_log_time()
    except Exception:
        pass
    return jsonify({"available": True, "rows": rows, "total": total,
                    "page": page, "per": per, "latest_log": latest})


@api.get("/raw-logs/export")
@login_required
def raw_logs_export():
    """CSV of the raw logs matching the current filters (real ES data, capped
    at 5,000 rows — the cap is stated in the UI, nothing silent)."""
    from app.services.siem_service import siem_service
    start, end, err = _parse_date_range()
    if err:
        return jsonify({"error": err}), 400
    rows, total = siem_service.search_raw_logs(
        q=(request.args.get("q") or "").strip() or None,
        source_ip=(request.args.get("ip") or "").strip() or None,
        start=start, end=end, page=1, per=5000,
        order=request.args.get("order") or "desc")
    if rows is None:
        return jsonify({"error": "Elasticsearch is unavailable"}), 503
    import csv
    import io as _io
    buf = _io.StringIO()
    wcsv = csv.writer(buf)
    wcsv.writerow(["timestamp", "source_ip", "dest", "message"])
    for r in rows:
        wcsv.writerow([r.get("timestamp"), r.get("source_ip"),
                       r.get("dest"), r.get("message")])
    out = _io.BytesIO(buf.getvalue().encode("utf-8-sig"))
    return send_file(out, mimetype="text/csv", as_attachment=True,
                     download_name="cyren_raw_logs.csv")


@api.post("/raw-logs/escalate")
@login_required
def raw_logs_escalate():
    """Analyst decides a 'no event' log IS worth acting on: build a real event
    from the raw log(s) sharing its source IP + rule, then run it through the
    normal pipeline so it can be ticketed / chained like any other event."""
    # every signed-in analyst or manager may escalate: raising a suspicion is
    # not the same as approving a block (that decision still needs its cap)
    from app.services.siem_service import siem_service
    data = request.get_json(force=True)
    ip = (data.get("source_ip") or "").strip()
    if not ip or ip == "unknown":
        return jsonify({"error": "this log has no usable source IP"}), 400

    # an event may already cover this IP — don't create a duplicate
    existing = Event.query.filter_by(source_ip=ip).first()
    if existing:
        return jsonify({"ok": True, "event_id": existing.id, "existing": True})

    # pull this IP's recent raw logs straight from ES and run them through the
    # SAME multi-agent pipeline every other event uses (triage → attack_type,
    # investigation → MITRE/summary, correlation → chaining)
    rows, _ = siem_service.search_raw_logs(source_ip=ip, page=1, per=200)
    if not rows:
        return jsonify({"error": "could not read this IP's logs from Elasticsearch"}), 400
    msgs = [r.get("message") for r in rows if r.get("message")]
    times = sorted(r["timestamp"] for r in rows if r.get("timestamp"))
    event = {
        "source_ip": ip, "dest_ip": rows[0].get("dest"),
        "rule": "Analyst-escalated logs", "log_count": len(rows),
        "raw_logs": msgs[:50], "severity": "medium", "risk_score": 50,
        "first_seen": times[0] if times else "", "last_seen": times[-1] if times else "",
    }
    from app.services.event_service import persist_pipeline_result
    try:
        state = run_pipeline(event)
        e = persist_pipeline_result(state)
    except Exception as exc:
        return jsonify({"error": "pipeline failed: %s" % exc}), 500
    _audit("event_escalated",
           "escalated raw logs from %s into event #%d (%s)"
           % (ip, e.id, e.attack_type or "Unclassified"))
    db.session.commit()

    # the analyst explicitly raised this, so a TICKET must exist afterwards:
    # the sweep covers high/uncertain-awaiting; anything else gets a manual one
    from app.services.ticket_service import auto_raise, _title_for, _description_for
    auto_raise()
    row = db.session.execute(db.text("SELECT ticket_id FROM ticket_events WHERE event_id = :i"),
                             {"i": e.id}).fetchone()
    tk_id = row[0] if row else None
    if tk_id is None:
        # created_at stays NOW (when the analyst escalated) so the ticket is
        # findable under today's date; the EVENT keeps the log's real timestamp.
        # The description is left for the ESCALATING ANALYST to write — the AI's
        # assessment is offered on demand via "Check with AI", not forced in.
        t = Ticket(title=_title_for([e]),
                   description=("Escalated from raw logs by %s. " % current_user.username)
                               + _DESC_PLACEHOLDER,
                   source_ip=e.source_ip, chain_id=e.chain_id,
                   status="queue", raised_by="manual")
        t.events = [e]
        db.session.add(t)
        db.session.flush()
        db.session.add(TicketActivity(ticket_id=t.id, user_id=current_user.id,
                                      text="Raised from a raw-log escalation"))
        _notify_all("ticket_raised", t.id,
                    "%s escalated raw logs into ticket T-%d — %s"
                    % (current_user.username, t.id, t.title or ""),
                    exclude_id=current_user.id)
        db.session.commit()
        tk_id = t.id
    else:
        # auto_raise ticketed it a moment ago, but the TRIGGER was this
        # analyst's escalation: mark it manual so it isn't shown as AUTO
        t = Ticket.query.get(tk_id)
        if t and t.raised_by != "manual":
            t.raised_by = "manual"
            db.session.add(TicketActivity(ticket_id=t.id, user_id=current_user.id,
                                          text="Raised from a raw-log escalation"))
            db.session.commit()
    return jsonify({"ok": True, "event_id": e.id, "ticket_id": tk_id, "existing": False})


# ------------------------------------------------------------------- activity
@api.get("/me/activity")
@login_required
def my_activity():
    """Activity history of the signed-in analyst: event decisions (approve/
    dismiss) AND firewall actions (block/unblock/reblock), merged by time."""
    uid = current_user.id
    decisions = (Decision.query.filter_by(user_id=uid)
                 .order_by(Decision.created_at.desc()).all())
    counts = {"approved": 0, "dismissed": 0, "reverted": 0, "blocked": 0, "unblocked": 0}
    for d in decisions:
        counts[d.action] = counts.get(d.action, 0) + 1

    fw = (AuditLog.query
          .filter(AuditLog.user_id == uid,
                  AuditLog.action.in_(["ip_blocked", "ip_unblocked", "ip_reblocked"]))
          .order_by(AuditLog.created_at.desc()).all())
    for a in fw:
        counts["blocked" if a.action in ("ip_blocked", "ip_reblocked") else "unblocked"] += 1

    items = []
    for d in decisions:
        e = Event.query.get(d.event_id) if d.event_id else None
        items.append({"kind": "decision", "action": d.action, "label": d.label,
                      "source_ip": e.source_ip if e else None,
                      "attack_type": e.attack_type if e else None,
                      "event_id": d.event_id,
                      "created_at": d.created_at.isoformat() if d.created_at else None})
    for a in fw:
        items.append({"kind": "firewall", "action": a.action, "detail": a.detail,
                      "created_at": a.created_at.isoformat() if a.created_at else None})
    items.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return jsonify({"counts": counts, "recent": items[:12]})


@api.get("/export")
@login_required
def export_data():
    """One-click export of the current situation as CSV(s). `types` picks what to
    include; `from`/`to` scope the event-based items to the dashboard's range.
    Returns a single CSV if one item is chosen, otherwise a ZIP of CSVs. Only real
    data is exported (no fabricated rows)."""
    import csv
    import io
    import zipfile
    types = [t.strip() for t in (request.args.get("types") or "").split(",") if t.strip()]
    if not types:
        return jsonify({"error": "select at least one item to export"}), 400
    start, end, err = _parse_date_range()
    if err:
        return jsonify({"error": err}), 400

    def to_csv(header, rows):
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(header)
        for r in rows:
            w.writerow(["" if v is None else v for v in r])
        return buf.getvalue()

    files = {}
    ev = (_apply_date_range(Event.query, start, end).order_by(Event.id).all()
          if ("events" in types or "summary" in types) else [])

    if "summary" in types:
        by = {"high": 0, "uncertain": 0, "low": 0}
        for e in ev:
            if e.risk in by:
                by[e.risk] += 1
        files["summary.csv"] = to_csv(["metric", "value"], [
            ["logs_collected", sum((e.log_count or 0) for e in ev)],
            ["security_events", len(ev)],
            ["high_risk", by["high"]], ["uncertain_risk", by["uncertain"]], ["low_risk", by["low"]],
            ["awaiting_approval", sum(1 for e in ev if e.status == "awaiting")],
            ["blocked", sum(1 for e in ev if e.status == "blocked")],
        ])
    if "events" in types:
        files["security_events.csv"] = to_csv(
            ["id", "first_seen", "last_seen", "source_ip", "dest_ip", "attack_type",
             "rule", "risk", "confidence", "status", "log_count"],
            [[e.id, e.first_seen, e.last_seen, e.source_ip, e.dest_ip, e.attack_type,
              e.rule, e.risk, e.confidence, e.status, e.log_count] for e in ev])
    if "blocks" in types:
        bq = _apply_created_range(BlockedIP.query, BlockedIP.created_at, start, end)
        files["firewall_blocks.csv"] = to_csv(
            ["ip", "attack_type", "blocked_by", "active", "created_at"],
            [[b.ip, b.attack_type, b.blocked_by, b.active, b.created_at]
             for b in bq.order_by(BlockedIP.id.desc()).all()])
    if "assets" in types and current_user.has_cap("manage_assets"):
        # asset inventory is manager-only data — an analyst without the
        # capability gets a report WITHOUT it, not the whole thing
        from app.enrichment.asset_assessment import Asset
        files["assets.csv"] = to_csv(
            ["ip", "name", "criticality", "department", "owner", "description"],
            [[a.ip, a.name, a.criticality, a.department, a.owner, a.description]
             for a in Asset.query.order_by(Asset.id).all()])
    if "audit" in types and current_user.has_cap("manage_users"):
        unames = {u.id: u.username for u in User.query.all()}
        aq = _apply_created_range(
            AuditLog.query.filter(AuditLog.action.notin_(["login_failed", "login_success"])),
            AuditLog.created_at, start, end)
        files["audit_log.csv"] = to_csv(
            ["time", "action", "detail", "taken_by"],
            [[a.created_at, a.action, a.detail, unames.get(a.user_id) or ""]
             for a in aq.order_by(AuditLog.id.desc()).limit(2000).all()])

    if not files:
        return jsonify({"error": "nothing to export (check your selection / permissions)"}), 400

    if len(files) == 1:
        name, text = next(iter(files.items()))
        return send_file(io.BytesIO(text.encode("utf-8-sig")), mimetype="text/csv",
                         as_attachment=True, download_name="cyren_" + name)
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in files.items():
            z.writestr(name, text)
    zbuf.seek(0)
    return send_file(zbuf, mimetype="application/zip", as_attachment=True,
                     download_name="cyren_export.zip")


_ATTACH_DIR = os.path.join(_PROJECT_ROOT, "data", "report_attachments")


def _note_json(n, unames):
    d = n.to_dict()
    d["by"] = unames.get(n.user_id) or "unknown"
    d["deleted_by"] = unames.get(n.deleted_by) if n.deleted_at else None
    d["mine"] = n.user_id == current_user.id
    return d


@api.get("/report-notes")
@login_required
def list_report_notes():
    """The analyst comment thread of the Report Builder, oldest first (deleted
    ones stay as tombstones, like a ticket discussion)."""
    unames = {u.id: u.username for u in User.query.all()}
    return jsonify({"notes": [_note_json(n, unames)
                              for n in ReportNote.query.order_by(ReportNote.id.asc()).limit(200).all()],
                    "team": _ticket_team()})       # roster for the @ mention picker


def _report_mentions(n, text):
    """@name in a report comment -> bell notification for that teammate."""
    for name in set(re.findall(r"@([A-Za-z0-9_.-]+)", text or "")):
        u = User.query.filter_by(username=name, is_active=True).first()
        if u and u.id != current_user.id:
            _notify(u.id, "report_mention", n.id,
                    "%s mentioned you in a report comment" % current_user.username)


@api.post("/report-notes")
@login_required
def add_report_note():
    """Post a comment (multipart: text, optional image PNG/JPG <= 2 MB)."""
    text = (request.form.get("text") or "").strip()[:4000]
    f = request.files.get("image")
    if not text and not f:
        return jsonify({"error": "write a comment or attach an image"}), 400
    n = ReportNote(user_id=current_user.id, text=text or "(image)")
    db.session.add(n)
    db.session.flush()
    if f and f.filename:
        data = f.read()
        if len(data) > 2 * 1024 * 1024:
            db.session.rollback()
            return jsonify({"error": "image too large (2 MB limit)"}), 400
        kind = "png" if data[:8] == b"\x89PNG\r\n\x1a\n" else ("jpg" if data[:3] == b"\xff\xd8\xff" else None)
        if not kind:
            db.session.rollback()
            return jsonify({"error": "only PNG or JPG images are accepted"}), 400
        os.makedirs(_ATTACH_DIR, exist_ok=True)
        path = os.path.join(_ATTACH_DIR, f"note_{n.id}.{kind}")
        with open(path, "wb") as fh:
            fh.write(data)
        n.image_path = path
    _audit("report_note_added", "report comment #%d: %s%s"
           % (n.id, text[:200], " (with image)" if n.image_path else ""))
    _report_mentions(n, text)
    db.session.commit()
    unames = {u.id: u.username for u in User.query.all()}
    return jsonify({"ok": True, "note": _note_json(n, unames)}), 201


@api.patch("/report-notes/<int:nid>")
@login_required
def edit_report_note(nid):
    """The author rewords a comment; it is marked (edited) and audited."""
    n = ReportNote.query.get_or_404(nid)
    if n.user_id != current_user.id:
        return jsonify({"error": "you can only edit your own comments"}), 403
    if n.deleted_at:
        return jsonify({"error": "this comment was deleted"}), 400
    text = (request.get_json(force=True).get("text") or "").strip()[:4000]
    if not text:
        return jsonify({"error": "the comment cannot be empty"}), 400
    n.text = text
    n.edited_at = datetime.utcnow()
    _audit("report_note_edited", "report comment #%d edited: %s" % (n.id, text[:200]))
    _report_mentions(n, text)
    db.session.commit()
    unames = {u.id: u.username for u in User.query.all()}
    return jsonify({"ok": True, "note": _note_json(n, unames)})


@api.delete("/report-notes/<int:nid>")
@login_required
def delete_report_note(nid):
    """Author (or a user manager) removes a comment; it stays as a tombstone."""
    n = ReportNote.query.get_or_404(nid)
    if n.user_id != current_user.id and not current_user.has_cap("manage_users"):
        return jsonify({"error": "only the author can delete this comment"}), 403
    if not n.deleted_at:
        n.deleted_at = datetime.utcnow()
        n.deleted_by = current_user.id
        _audit("report_note_deleted", "report comment #%d deleted" % n.id)
        db.session.commit()
    return jsonify({"ok": True})


@api.get("/report-notes/<int:nid>/image")
@login_required
def report_note_image(nid):
    n = ReportNote.query.get_or_404(nid)
    if not n.image_path or not os.path.exists(n.image_path) or n.deleted_at:
        return jsonify({"error": "no image"}), 404
    return send_file(n.image_path)


@api.get("/export/report")
@login_required
def export_report():
    """A PDF 'situation report' for the selected range + sections, in the same
    styled layout as an incident report. ?download=1 saves it; otherwise it opens
    inline for viewing (mirrors the incident-report view/download)."""
    import io as _io
    from app.services.report_service import render_activity_report_bytes
    types = [t.strip() for t in (request.args.get("types") or "").split(",") if t.strip()]
    if not types and not (request.args.get("note_ids") or "").strip():
        return jsonify({"error": "select at least one section or tick a comment"}), 400
    start, end, err = _parse_date_range()
    if err:
        return jsonify({"error": err}), 400

    def fmt(v):
        return str(v).replace("T", " ")[:16] if v else "-"

    def _loc(v):
        """stored UTC (datetime or ISO string) -> local aware datetime, or None"""
        if not v:
            return None
        try:
            dt = v if isinstance(v, datetime) else datetime.fromisoformat(str(v).replace("Z", ""))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone()
        except (TypeError, ValueError):
            return None

    def fd(v):
        d = _loc(v); return d.strftime("%d-%m-%Y") if d else "-"

    _LABELS = {
        "ip_blocked": "IP blocked", "ip_unblocked": "IP unblocked", "ip_reblocked": "IP blocked again",
        "ip_whitelisted": "Added to whitelist", "ip_unwhitelisted": "Removed from whitelist",
        "event_dismissed": "Event marked false positive", "event_reopened": "False positive undone",
        "event_contained": "Event contained", "event_escalated": "Log lines escalated to an event",
        "ticket_created": "Ticket created", "ticket_updated": "Ticket updated",
        "ticket_assigned": "Ticket assigned", "ticket_status": "Ticket status changed",
        "ticket_closed": "Ticket closed", "ticket_deleted": "Ticket deleted",
        "user_created": "User created", "user_updated": "User updated", "user_deleted": "User deleted",
        "user_approved": "Account request approved", "login_success": "Signed in", "login_failed": "Sign-in failed",
        "asset_created": "Asset added", "asset_updated": "Asset updated", "asset_deleted": "Asset removed",
        "retrain_schedule_changed": "Retraining schedule changed",
    }

    def label(action):
        """audit action code -> words ("ip_blocked" -> "IP blocked")"""
        a = str(action or "")
        return _LABELS.get(a) or a.replace("_", " ").replace("ip ", "IP ").capitalize()

    def clean(detail):
        """drop the quoting around the address: "'1.2.3.4' - reason: x" -> "1.2.3.4, reason: x" """
        t = str(detail or "").strip()
        if t.startswith("'"):
            end = t.find("'", 1)
            if end > 0:
                addr, rest = t[1:end], t[end + 1:].strip()
                if rest.startswith("-"):
                    rest = rest[1:].strip()
                t = addr + (", " + rest if rest else "")
        return t

    def ft(v):
        d = _loc(v); return d.strftime("%I:%M:%S %p").lstrip("0") if d else "-"

    def pct(v):
        try:
            return f"{float(v) * 100:.0f}%"
        except (TypeError, ValueError):
            return "-"

    sections = {}
    ev = (_apply_date_range(Event.query, start, end).order_by(Event.id).all()
          if ("events" in types or "summary" in types) else [])
    if "summary" in types:
        by = {"high": 0, "uncertain": 0, "low": 0}
        for e in ev:
            if e.risk in by:
                by[e.risk] += 1
        sections["summary"] = {
            "logs_collected": sum((e.log_count or 0) for e in ev), "security_events": len(ev),
            "high_risk": by["high"], "uncertain_risk": by["uncertain"], "low_risk": by["low"],
            "awaiting": sum(1 for e in ev if e.status == "awaiting"),
            "blocked": sum(1 for e in ev if e.status == "blocked"),
        }
    def ids_of(name):
        """Optional explicit picks (?event_ids=1,2). None = everything in range."""
        raw = (request.args.get(name) or "").strip()
        if not raw:
            return None
        return [int(p) for p in raw.split(",") if p.strip().isdigit()]

    def want_details(name, has_ids):
        """?events_details=1 attaches FULL detail pages for the whole selection.
        When the flag is absent, explicit picks imply details (legacy)."""
        v = request.args.get(name)
        if v is None:
            return has_ids
        return v == "1"

    if "events" in types:
        ev_ids = ids_of("event_ids")
        ev_sel = (Event.query.filter(Event.id.in_(ev_ids)).order_by(Event.id).all()
                  if ev_ids else ev)
        sections["events"] = [[f"#{e.id}", fd(e.last_seen or e.first_seen), ft(e.last_seen or e.first_seen),
                               e.source_ip, e.attack_type, e.risk, pct(e.confidence), e.status]
                              for e in ev_sel]
        if want_details("events_details", bool(ev_ids)):
            sections["event_details"] = [_state_from_event(e) for e in ev_sel]
    if "chains" in types:
        ch_ids = ids_of("chain_ids")
        ch_det = want_details("chains_details", bool(ch_ids))
        tk_by_chain = {t.chain_id: t.id for t in Ticket.query.filter(Ticket.chain_id.isnot(None)).all()}
        rows, details = [], []
        chq = (AttackChain.query.filter(AttackChain.id.in_(ch_ids)) if ch_ids
               else AttackChain.query)
        for ch in chq.order_by(AttackChain.id).all():
            # a chain is in range if its active window overlaps the range at all
            if not ch_ids:
                if start and ch.last_seen and ch.last_seen < start:
                    continue
                if end and ch.first_seen and ch.first_seen >= end:
                    continue
            rows.append([f"#C-{ch.id}", ch.source_ip,
                         ch.stage_count or len(ch.stages or []), ch.highest_risk or "-",
                         fd(ch.first_seen), ft(ch.first_seen), fd(ch.last_seen), ft(ch.last_seen),
                         (f"T-{tk_by_chain[ch.id]}" if ch.id in tk_by_chain else "-")])
            if ch_det:
                details.append({
                    "ref": f"#C-{ch.id}", "source_ip": ch.source_ip,
                    "risk": ch.highest_risk or "-", "predicted_next": ch.predicted_next,
                    "first_date": fd(ch.first_seen), "first_time": ft(ch.first_seen),
                    "last_date": fd(ch.last_seen), "last_time": ft(ch.last_seen),
                    "ticket": (f"T-{tk_by_chain[ch.id]}" if ch.id in tk_by_chain else "-"),
                    "stages": [[i, s.get("tactic") or s.get("phase") or "-",
                                s.get("attack_type") or "-",
                                (", ".join(s.get("mitre")) if isinstance(s.get("mitre"), list)
                                 else (s.get("mitre") or "-")),
                                fd(s.get("timestamp")), ft(s.get("timestamp"))]
                               for i, s in enumerate(ch.stages or [], start=1)],
                })
        sections["chains"] = rows
        if ch_det:
            sections["chain_details"] = details
    if "tickets" in types:
        tk_ids = ids_of("ticket_ids")
        tk_det = want_details("tickets_details", bool(tk_ids))
        unames_t = {u.id: u.username for u in User.query.all()}
        tq2 = (Ticket.query.filter(Ticket.id.in_(tk_ids)) if tk_ids
               else _apply_created_range(Ticket.query, Ticket.created_at, start, end))
        tks = tq2.order_by(Ticket.id).all()
        sections["tickets"] = [[f"T-{t.id}", fd(t.created_at), ft(t.created_at), (t.title or "")[:48],
                                t.source_ip or "-", t.risk() or "-", t.status or "-",
                                unames_t.get(t.assignee_id) or "-"] for t in tks]
        if tk_det:
            sections["ticket_details"] = [{
                "id": t.id, "title": t.title, "status": t.status,
                "owner": unames_t.get(t.assignee_id) or "unassigned",
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "description": _clean_desc(t.description), "source_ip": t.source_ip,
                "risk": t.risk(), "close_reason": t.close_reason,
                "close_note": t.close_note, "closed_by": unames_t.get(t.closed_by),
                "closed_at": t.closed_at.isoformat() if t.closed_at else None,
                "events": [f"#{e.id}" for e in t.events],
                # response history: everything done on the ticket (raised /
                # assigned / status changes / closed — who & when) ...
                "activity": [[fd(a.created_at), ft(a.created_at), a.text or "-",
                              unames_t.get(a.user_id) or "system"]
                             for a in TicketActivity.query.filter_by(ticket_id=t.id)
                             .order_by(TicketActivity.created_at).all()],
                # ... plus the firewall block/unblock trail for its source IP
                "response_log": [[fd(r["created_at"]), ft(r["created_at"]), label(r["action"]), clean(r["detail"])]
                                 for r in _response_log(t.source_ip)],
                "comments": _people_rows(TicketComment.query.filter_by(ticket_id=t.id)
                                         .order_by(TicketComment.created_at).all(), unames_t),
            } for t in tks]
    if "blocks" in types:
        bq = _apply_created_range(BlockedIP.query, BlockedIP.created_at, start, end)
        sections["blocks"] = [[b.ip, b.attack_type, b.blocked_by, ("yes" if b.active else "no"),
                               fd(b.created_at), ft(b.created_at)]
                              for b in bq.order_by(BlockedIP.id.desc()).all()]
    if "assets" in types and current_user.has_cap("manage_assets"):
        # asset inventory is manager-only data — an analyst without the
        # capability gets a report WITHOUT it, not the whole thing
        from app.enrichment.asset_assessment import Asset
        sections["assets"] = [[a.ip, a.name, a.criticality, a.department, a.owner, a.description]
                              for a in Asset.query.order_by(Asset.id).all()]
    if "audit" in types and current_user.has_cap("manage_users"):
        unames = {u.id: u.username for u in User.query.all()}
        aq = _apply_created_range(
            AuditLog.query.filter(AuditLog.action.notin_(["login_failed", "login_success"])),
            AuditLog.created_at, start, end)
        sections["audit"] = [[fd(a.created_at), ft(a.created_at), label(a.action), clean(a.detail), unames.get(a.user_id) or ""]
                             for a in aq.order_by(AuditLog.id.desc()).limit(300).all()]

    if "rawlogs" in types:
        # live SIEM rows — either the analyst's hand-picked ES documents
        # (?rawlog_ids=...) or everything matching the card's filters in range
        from app.services.siem_service import siem_service
        rl_ids = [p for p in (request.args.get("rawlog_ids") or "").split(",") if p.strip()]
        rl_rows, rl_note = [], None
        if rl_ids:
            docs = siem_service.fetch_raw_logs_by_ids(rl_ids[:300])
            if docs is None:
                rl_note = "SIEM (Elasticsearch) was unreachable at export time."
            else:
                rl_rows = docs
        else:
            # the raw-logs card has its OWN date pickers (rawlog_from/to); they
            # override the report's From/To range when set
            def _pd(v):
                v = (v or "").strip()
                if not v:
                    return None
                try:
                    return datetime.fromisoformat(v.replace("Z", "")[:19])
                except ValueError:
                    return None
            rl_start = _pd(request.args.get("rawlog_from")) or start
            rl_end = _pd(request.args.get("rawlog_to")) or end
            docs, rl_total = siem_service.search_raw_logs(
                q=(request.args.get("rawlog_q") or "").strip() or None,
                source_ip=(request.args.get("rawlog_ip") or "").strip() or None,
                start=rl_start, end=rl_end, page=1, per=200, order="desc")
            if docs is None:
                rl_note = "SIEM (Elasticsearch) was unreachable at export time."
            else:
                rl_rows = docs
                if rl_total > len(docs):
                    rl_note = (f"showing the newest {len(docs)} of {rl_total:,} matching "
                               "log lines — narrow the range or pick rows for a full set")
        def _split_ts(v):
            return (fd(v), ft(v))
        sections["rawlogs"] = [[_split_ts(r.get("timestamp"))[0], _split_ts(r.get("timestamp"))[1],
                                r.get("source_ip") or "-",
                                (r.get("message") or "")[:180]] for r in rl_rows]
        if rl_note:
            sections["rawlogs_note"] = rl_note

    if not sections and not (ids_of("note_ids") or []):     # comments alone make a report too
        return jsonify({"error": "nothing to include (check your selection / permissions)"}), 400

    # the bounds arrive in UTC (the page converts the analyst's local pick);
    # the label must show the LOCAL dates the analyst chose, and `end` is
    # exclusive, so step back a minute before naming its day
    def _lbl(d):
        return d.replace(tzinfo=timezone.utc).astimezone().strftime("%d-%m-%Y")
    label = (f"{_lbl(start)} to {_lbl(end - timedelta(minutes=1))}" if start and end
             else f"from {_lbl(start)}" if start else "All time")
    # free text the analyst typed for this report: it goes into the PDF under
    # their name AND into the audit log, so nothing in a report is unrecorded
    # the analyst comments ticked in the builder (stored, with author and time)
    unames_n = {u.id: u.username for u in User.query.all()}
    notes = []
    for nid in (ids_of("note_ids") or []):
        n = ReportNote.query.get(nid)
        if n and not n.deleted_at:
            notes.append({"created_at": n.created_at.isoformat() if n.created_at else None,
                          "by": unames_n.get(n.user_id) or "unknown", "text": n.text,
                          "edited": bool(n.edited_at),
                          "image": n.image_path if n.image_path and os.path.exists(n.image_path) else None})
    if notes:
        _audit("report_generated", "SOC Activity Report (%s) with %d analyst comment(s)" % (label, len(notes)))
        db.session.commit()
    pdf = render_activity_report_bytes({
        "report_title": "SOC Activity Report",
        "period": label if (start or end) else None,     # 'All time' says nothing, so it is left out
        "generated_by": current_user.username,
        # the section order the user set in the Report Builder (?order=a,b,c)
        "order": [o.strip() for o in (request.args.get("order") or "").split(",") if o.strip()],
        "analyst_notes": notes,
        "hide_risk_badge": True, "sections": sections,
    })
    if not pdf:
        return jsonify({"error": "PDF engine unavailable"}), 500
    return send_file(_io.BytesIO(pdf), mimetype="application/pdf",
                     as_attachment=bool(request.args.get("download")),
                     download_name="cyren_activity_report.pdf")


# ---------------------------------------------------------------- enrichment
@api.get("/assets")
@login_required
def list_assets():
    from app.enrichment.asset_assessment import Asset
    return jsonify([a.to_dict() for a in Asset.query.all()])


_CRITICALITY = ("critical", "high", "medium", "low", "unknown")


def _svc(v):
    """Normalise the services field to a list (accepts a comma-separated string)."""
    if isinstance(v, str):
        return [s.strip() for s in v.split(",") if s.strip()]
    return v or []


@api.get("/assets/overview")
@login_required
def assets_overview():
    """Asset inventory plus honest KPI tiles for the Asset Management page.
    'monitored' = assets whose IP has actually appeared in an event."""
    from app.enrichment.asset_assessment import Asset, resolve_dest_ip
    all_events = Event.query.all()
    # the SIEM records the target by hostname ("target-server"), so resolve
    # destinations to inventory IPs the same way the enrichment does, otherwise
    # the attacked host itself would never count as seen
    src_ips = {e.source_ip for e in all_events}
    dst_ips = {resolve_dest_ip(e.dest_ip) for e in all_events}
    assets = Asset.query.order_by(Asset.id).all()
    rows = []
    for a in assets:
        rows.append({**a.to_dict(),
                     "as_source": a.ip in src_ips,      # this asset attacked: internal attack
                     "as_target": a.ip in dst_ips,      # this asset was attacked
                     "monitored": a.ip in src_ips or a.ip in dst_ips})
    tiers = {k: sum(1 for a in assets if (a.criticality or "").lower() == k)
             for k in ("critical", "high", "medium", "low")}
    crit, high = tiers["critical"], tiers["high"]
    return jsonify({
        "assets": rows,
        "kpi": {"total": len(assets), "critical": crit, "high": high,
                "medium": tiers["medium"], "low": tiers["low"],
                "high_criticality": crit + high,
                "internal_attack": sum(1 for r in rows if r["as_source"]),
                "monitored": sum(1 for r in rows if r["monitored"])},
    })


@api.post("/assets")
@login_required
def create_asset():
    from app.enrichment.asset_assessment import Asset
    deny = _require_cap("manage_assets")
    if deny:
        return deny
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "IP address is required"}), 400
    if not (data.get("name") or "").strip():
        return jsonify({"error": "asset name is required"}), 400
    for _f in ("department", "owner"):
        if not (data.get(_f) or "").strip():
            return jsonify({"error": f"{_f} is required"}), 400
    if Asset.query.filter_by(ip=ip).first():
        return jsonify({"error": f"An asset with IP {ip} already exists"}), 409
    crit = (data.get("criticality") or "unknown").strip().lower()
    if crit not in _CRITICALITY:
        return jsonify({"error": "invalid criticality"}), 400
    a = Asset(ip=ip, name=(data.get("name") or "").strip() or None, criticality=crit,
              department=(data.get("department") or "").strip() or None,
              owner=(data.get("owner") or "").strip() or None,
              description=(data.get("description") or "").strip() or None)
    db.session.add(a)
    _audit("asset_created", f"'{a.name or a.ip}' ({a.ip}), criticality {a.criticality}")
    db.session.commit()
    return jsonify({"ok": True, "asset": a.to_dict()}), 201


@api.patch("/assets/<int:asset_id>")
@login_required
def update_asset(asset_id):
    from app.enrichment.asset_assessment import Asset
    deny = _require_cap("manage_assets")
    if deny:
        return deny
    a = Asset.query.get_or_404(asset_id)
    data = request.get_json(silent=True) or {}
    changes = []
    if "criticality" in data:
        crit = (data.get("criticality") or "unknown").strip().lower()
        if crit not in _CRITICALITY:
            return jsonify({"error": "invalid criticality"}), 400
        if crit != a.criticality:
            changes.append(f"criticality {a.criticality} -> {crit}")
        a.criticality = crit
    if "name" in data and not (data.get("name") or "").strip():
        return jsonify({"error": "asset name is required"}), 400
    for _f in ("department", "owner"):
        if _f in data and not (data.get(_f) or "").strip():
            return jsonify({"error": f"{_f} is required"}), 400
    for f in ("name", "department", "owner", "description"):
        if f in data:
            newv = (data.get(f) or "").strip() or None
            if newv != getattr(a, f):
                changes.append(f)
            setattr(a, f, newv)
    if data.get("ip"):
        ip = data["ip"].strip()
        if ip != a.ip and Asset.query.filter_by(ip=ip).first():
            return jsonify({"error": f"IP {ip} already used by another asset"}), 409
        if ip != a.ip:
            changes.append("ip")
        a.ip = ip
    if "services" in data:
        a.services = _svc(data.get("services"))
    rescored = contained = 0
    if any(c.startswith("criticality ") for c in changes):
        # the criticality bump is part of every event's risk label, so re-score
        # with the current thresholds and follow the policy through
        hi = float(Setting.get("high_risk_threshold") or settings.HIGH_RISK_THRESHOLD)
        lo = float(Setting.get("low_risk_threshold") or settings.LOW_RISK_THRESHOLD)
        rescored = _rescore_events(hi, lo)
        contained = _contain_after_rescore("asset criticality change")
    if changes:
        _audit("asset_updated", f"'{a.name or a.ip}' ({a.ip}): {', '.join(changes)}"
               + (f" ({rescored} event(s) re-scored" + (f", {contained} auto-contained" if contained else "") + ")"
                  if rescored or contained else ""))
    db.session.commit()
    return jsonify({"ok": True, "asset": a.to_dict(), "rescored": rescored, "contained": contained})


@api.delete("/assets/<int:asset_id>")
@login_required
def delete_asset(asset_id):
    from app.enrichment.asset_assessment import Asset
    deny = _require_cap("manage_assets")
    if deny:
        return deny
    a = Asset.query.get_or_404(asset_id)
    _audit("asset_deleted", f"'{a.name or a.ip}' ({a.ip})")
    db.session.delete(a)
    db.session.commit()
    return jsonify({"ok": True})


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


# ------------------------------------------------------------ blocklist feed
@api.get("/blocklist")
def blocklist_feed():
    """
    Plain-text feed of the actively blocked source IPs, one per line.

    Consumed by the enforcement agent on the target host (ipset sync via
    systemd timer), which cannot hold a browser session — so this endpoint
    is authenticated with a static token instead: set BLOCKLIST_TOKEN in
    .env and send it as the X-CyREN-Token header (or ?token=). With no
    token configured the feed stays disabled.
    """
    import hmac
    from flask import Response
    from config.settings import settings

    token = getattr(settings, "BLOCKLIST_TOKEN", "") or ""
    if not token:
        return Response("blocklist feed disabled (set BLOCKLIST_TOKEN)\n",
                        status=503, mimetype="text/plain")
    supplied = request.headers.get("X-CyREN-Token") or request.args.get("token", "")
    if not hmac.compare_digest(supplied, token):
        return Response("forbidden\n", status=403, mimetype="text/plain")

    ips = sorted({b.ip for b in BlockedIP.query.filter_by(active=True).all() if b.ip})
    return Response("\n".join(ips) + ("\n" if ips else ""), mimetype="text/plain")


# ------------------------------------------------------------- model retrain
# One retrain at a time, run in a background thread; status is polled by the
# Settings page. Uses the existing offline scripts, nothing is simulated.
_retrain_state = {"running": False, "started": None, "finished": None,
                  "ok": None, "log": "", "trigger": None, "last_duration": None,
                  "cancelled": False}
_retrain_proc = {"p": None}          # the subprocess currently running, for Cancel


def _last_retrain_duration():
    """Seconds the previous retraining run took (kept in Settings so it survives
    a restart); None until one run has completed."""
    if _retrain_state.get("last_duration") is not None:
        return _retrain_state["last_duration"]
    row = db.session.get(Setting, "retrain_last_duration")
    try:
        return float(row.value) if row and row.value else None
    except ValueError:
        return None


def _set_setting(key, value):
    row = db.session.get(Setting, key)
    if row is None:
        row = Setting(key=key)
        db.session.add(row)
    row.value = str(value)
    db.session.commit()


def _backup_model():
    """Snapshot the current model + rule map to data/models/backups before a
    retrain, so a bad run can be rolled back. Best-effort; never blocks retrain."""
    import shutil
    from config.settings import settings as cfg
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(_PROJECT_ROOT, "data", "models", "backups")
    try:
        os.makedirs(backup_dir, exist_ok=True)
        for src in (cfg.XGBOOST_MODEL_PATH, cfg.RULE_MAP_PATH):
            p = src if os.path.isabs(src) else os.path.join(_PROJECT_ROOT, src)
            if os.path.exists(p):
                shutil.copy2(p, os.path.join(backup_dir, os.path.basename(p) + "." + ts + ".bak"))
    except Exception as exc:                           # noqa: BLE001
        print(f"[retrain] model backup skipped: {exc}")


def _parse_hhmm(s):
    try:
        h, m = (s or "02:00").split(":")
        return max(0, min(23, int(h))), max(0, min(59, int(m)))
    except Exception:                                  # noqa: BLE001
        return 2, 0


def _month_last_day(d):
    import calendar
    return calendar.monthrange(d.year, d.month)[1]


def _is_sched_day(when, interval, dow, dom):
    """Is `when` a scheduled retrain day? daily=every day, weekly=on weekday `dow`
    (Mon=0), monthly=on `dom` (or the month's last day if dom is beyond it)."""
    if interval == 24:
        return True
    if interval == 168:
        return when.weekday() == dow
    if interval == 720:
        return when.day == min(dom, _month_last_day(when))
    return False


def _retrain_schedule_label():
    """Human label of the stored auto-retrain schedule, e.g. 'weekly on Mon at 02:00'
    or 'off' (used for the audit trail: old -> new)."""
    try:
        hours = int(Setting.get("retrain_interval_hours", "0") or 0)
    except (TypeError, ValueError):
        hours = 0
    if hours == 0:
        return "off"
    tod = Setting.get("retrain_time", "02:00")
    try:
        dow = int(Setting.get("retrain_dow", "0") or 0)
    except (TypeError, ValueError):
        dow = 0
    try:
        dom = int(Setting.get("retrain_dom", "1") or 1)
    except (TypeError, ValueError):
        dom = 1
    if hours == 168:
        return f"weekly on {['Mon','Tue','Wed','Thu','Fri','Sat','Sun'][dow % 7]} at {tod}"
    if hours == 720:
        return f"monthly on day {dom} at {tod}"
    return f"daily at {tod}"


def _retrain_schedule_info():
    """Current auto-retrain schedule: mode (interval hours, 0=off), time-of-day,
    weekday/day-of-month, last run and the next due time (SERVER-LOCAL time)."""
    try:
        interval = int(Setting.get("retrain_interval_hours", "0") or 0)
    except (TypeError, ValueError):
        interval = 0
    tod = Setting.get("retrain_time", "02:00")
    try:
        dow = int(Setting.get("retrain_dow", "0") or 0)
    except (TypeError, ValueError):
        dow = 0
    try:
        dom = int(Setting.get("retrain_dom", "1") or 1)
    except (TypeError, ValueError):
        dom = 1
    last = Setting.get("retrain_last")
    nxt = None
    if interval > 0:
        hh, mm = _parse_hhmm(tod)
        now = datetime.now()
        cand = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        for _ in range(400):                           # scan forward for the next match
            if cand > now and _is_sched_day(cand, interval, dow, dom):
                nxt = cand.isoformat()
                break
            cand += timedelta(days=1)
    return {"interval_hours": interval, "time": tod, "dow": dow, "dom": dom,
            "last": last, "next": nxt}


def maybe_auto_retrain():
    """Called each scheduler cycle (inside an app context). Fire a retrain when
    today is the scheduled day and the local clock is past the chosen time, at
    most once per scheduled day."""
    info = _retrain_schedule_info()
    interval = info["interval_hours"]
    if interval <= 0 or _retrain_state["running"]:
        return
    now = datetime.now()
    hh, mm = _parse_hhmm(info["time"])
    sched_today = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if now < sched_today or not _is_sched_day(now, interval, info["dow"], info["dom"]):
        return
    last = None
    if info["last"]:
        try:
            last = datetime.fromisoformat(info["last"])
        except Exception:                              # noqa: BLE001
            last = None
    if last is not None and last >= sched_today:
        return                                         # already ran since today's time
    import threading
    from flask import current_app
    _set_setting("retrain_last", now.isoformat())
    _retrain_state.update(running=True, started=datetime.utcnow().isoformat(),
                          finished=None, ok=None, log="", trigger="auto")
    db.session.add(AuditLog(user_id=None, action="retrain_started",
                            detail=f"automatic, {_retrain_schedule_label()}"))
    db.session.commit()
    threading.Thread(target=_retrain_worker, daemon=True, name="cyren-auto-retrain",
                     kwargs={"app": current_app._get_current_object(), "user_id": None}).start()


def _retrain_worker(app=None, user_id=None):
    import subprocess
    import sys as _sys
    import re as _re

    _backup_model()   # snapshot the current model first (rollback safety)
    # export the labelled set from the DB (IP lists + analyst decisions), then
    # train ON that set. The built-in synthetic patterns are only added when the
    # real set is missing a class or is very thin (cold start); once enough real
    # attack AND benign rows exist the model learns from real traffic alone.
    steps = [
        [_sys.executable, os.path.join("scripts", "export_training_set.py")],
        [_sys.executable, os.path.join("scripts", "train_triage.py"),
         "--data", os.path.join("data", "training_set.csv"), "--synthetic-if-needed"],
    ]
    chunks, ok = [], True
    _retrain_state["cancelled"] = False
    for cmd in steps:
        if _retrain_state.get("cancelled"):
            break
        try:
            p = subprocess.Popen(cmd, cwd=_PROJECT_ROOT, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True)
            _retrain_proc["p"] = p
            try:
                out, _ = p.communicate(timeout=1800)
            except subprocess.TimeoutExpired:
                p.kill()
                out, _ = p.communicate()
            _retrain_proc["p"] = None
            chunks.append("$ python " + cmd[1] + "\n" + (out or ""))
            if _retrain_state.get("cancelled"):
                chunks.append("Cancelled by the user; the previous model is unchanged.")
                ok = False
                break
            if p.returncode != 0:
                ok = False
                break
        except Exception as exc:                      # noqa: BLE001
            _retrain_proc["p"] = None
            chunks.append("$ python " + cmd[1] + "\nfailed: " + str(exc))
            ok = False
            break
    finished = datetime.utcnow()
    duration = None
    try:
        duration = round((finished - datetime.fromisoformat(_retrain_state["started"])).total_seconds(), 1)
    except Exception:                                  # noqa: BLE001
        pass
    # the ChromaDB client prints a telemetry warning on every start; it is noise
    log = "\n".join(ln for ln in "\n\n".join(chunks).splitlines()
                    if "Failed to send telemetry event" not in ln)
    _retrain_state.update(running=False, ok=ok, finished=finished.isoformat(),
                          log=log[-8000:], last_duration=duration)
    if app is None:
        return
    with app.app_context():
        try:
            if ok and duration is not None:
                _set_setting("retrain_last_duration", str(duration))
            # outcome -> audit trail (a cancel is audited by the cancel request itself)
            if not _retrain_state.get("cancelled"):
                dur_txt = f"{duration:.0f} s" if duration is not None else "an unknown time"
                if ok:
                    bits = [f"in {dur_txt}"]
                    m = _re.search(r"\((\d+) rows\)", log)
                    if m:
                        bits.append(f"{m.group(1)} rows exported")
                    m = _re.search(r"Accuracy:\s*([\d.]+)", log)
                    if m:
                        bits.append(f"accuracy {m.group(1)}")
                    detail = ", ".join(bits)
                    action = "retrain_finished"
                else:
                    detail = f"after {dur_txt}, see the Settings page output"
                    action = "retrain_failed"
                db.session.add(AuditLog(user_id=user_id, action=action, detail=detail))
            db.session.commit()
        except Exception as exc:                       # noqa: BLE001
            db.session.rollback()
            print(f"[retrain] audit write failed: {exc}")


@api.post("/model/retrain")
@login_required
def start_retrain():
    import threading

    deny = _require_cap("retrain_model")
    if deny:
        return deny
    if _retrain_state["running"]:
        return jsonify({"ok": False, "error": "A retraining run is already in progress"}), 409
    from flask import current_app
    _set_setting("retrain_last", datetime.now().isoformat())   # local, drives the schedule
    _retrain_state.update(running=True, started=datetime.utcnow().isoformat(),
                          finished=None, ok=None, log="", trigger="manual")
    _audit("retrain_started", "manual")
    db.session.commit()
    threading.Thread(target=_retrain_worker, daemon=True, name="cyren-retrain",
                     kwargs={"app": current_app._get_current_object(),
                             "user_id": getattr(current_user, "id", None)}).start()
    return jsonify({"ok": True})


@api.post("/model/retrain/cancel")
@login_required
def cancel_retrain():
    """Stop the retraining run in progress. The trainer only writes the model
    file at its very end, so stopping it early leaves the previous model as is."""
    deny = _require_cap("retrain_model")
    if deny:
        return deny
    if not _retrain_state["running"]:
        return jsonify({"ok": False, "error": "No retraining run is in progress"}), 409
    _retrain_state["cancelled"] = True
    p = _retrain_proc.get("p")
    if p is not None:
        try:
            p.terminate()
        except Exception:                              # noqa: BLE001
            pass
    _audit("retrain_cancelled", "by the user, the previous model is unchanged")
    db.session.commit()
    return jsonify({"ok": True})


@api.get("/model/retrain")
@login_required
def retrain_status():
    return jsonify({**_retrain_state, "last_duration": _last_retrain_duration(),
                    "schedule": _retrain_schedule_info()})


@api.post("/model/retrain-schedule")
@login_required
def set_retrain_schedule():
    """Configure automatic retraining. Needs 'retrain_model'. interval_hours:
    0 = off, 24 = daily, 168 = weekly, 720 = monthly."""
    deny = _require_cap("retrain_model")
    if deny:
        return deny
    data = request.get_json(force=True)
    try:
        hours = int(data.get("interval_hours"))
    except (TypeError, ValueError):
        return jsonify({"error": "interval_hours must be a whole number"}), 400
    if hours not in (0, 24, 168, 720):
        return jsonify({"error": "choose off / daily / weekly / monthly"}), 400
    prev = _retrain_schedule_label()
    tod = (data.get("time") or "02:00").strip()
    hh, mm = _parse_hhmm(tod)
    tod = f"{hh:02d}:{mm:02d}"
    try:
        dow = max(0, min(6, int(data.get("dow", 0))))
    except (TypeError, ValueError):
        dow = 0
    try:
        dom = max(1, min(31, int(data.get("dom", 1))))
    except (TypeError, ValueError):
        dom = 1
    _set_setting("retrain_interval_hours", hours)
    _set_setting("retrain_time", tod)
    _set_setting("retrain_dow", dow)
    _set_setting("retrain_dom", dom)
    new = _retrain_schedule_label()
    if new != prev:
        _audit("retrain_schedule_changed", f"Auto-retrain {prev} -> {new}")
        db.session.commit()
    return jsonify({"ok": True, "schedule": _retrain_schedule_info()})
