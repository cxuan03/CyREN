"""
Event service: persists a pipeline result to the database.

This is the single place where a finished AgentState becomes rows in the
Event / AttackChain / BlockedIP / Report tables. Both the /api/ingest endpoint
and the background scheduler call it, so the two paths cannot drift apart.

Dedup rule: an aggregated event is identified by (source_ip, rule). If an
open event for that pair already exists, it is merged (log_count and analysis
updated, last_seen refreshed) instead of duplicated.
"""
from datetime import datetime

from app.models.db import db, Event, AttackChain, BlockedIP, Report, AuditLog

_STATUS_MAP = {"blocked": "blocked", "awaiting_approval": "awaiting", "logged": "logged",
               "whitelisted": "logged"}


def _parse_ts(value, default=None):
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            pass
    return default or datetime.utcnow()


def suppressed_event(source_ip, rule):
    """The dismissed event that is still suppressing repeats of this
    (source_ip, rule) pair, or None. While one exists, the scheduler folds new
    activity into it and skips the pipeline entirely (no new event, no block,
    no email) until suppressed_until passes."""
    if not source_ip or not rule:
        return None
    return (Event.query
            .filter_by(source_ip=source_ip, rule=rule, status="dismissed")
            .filter(Event.suppressed_until.isnot(None),
                    Event.suppressed_until > datetime.utcnow())
            .order_by(Event.id.desc())
            .first())


def fold_into_suppressed(e: Event, state: dict) -> Event:
    """Attach a repeat burst to a suppressed event: refresh last_seen, grow the
    log count, and count the repeat. The event stays dismissed and no response
    is taken."""
    now = datetime.utcnow()
    ls = _parse_ts(state.get("last_seen"), now)
    if e.last_seen is None or ls > e.last_seen:
        e.last_seen = ls
    e.log_count = max(e.log_count or 0, state.get("log_count", 0))
    e.suppress_hits = (e.suppress_hits or 0) + 1
    db.session.commit()
    return e


def _upsert_chain(state: dict, now: datetime) -> AttackChain:
    """Create or update the attack chain for this source IP."""
    chain = (AttackChain.query
             .filter_by(source_ip=state.get("source_ip"))
             .order_by(AttackChain.id.desc())
             .first())
    if chain is None:
        chain = AttackChain(source_ip=state.get("source_ip"), first_seen=now)
        db.session.add(chain)

    stages = state.get("chain_stages") or []
    chain.stages = stages
    chain.stage_count = len(stages)
    chain.highest_risk = state.get("chain_risk")
    chain.predicted_next = state.get("predicted_next")
    chain.last_seen = now
    if chain.first_seen is None:
        chain.first_seen = now
    return chain


def persist_pipeline_result(state: dict) -> Event:
    """Save one finished pipeline state; returns the (new or merged) Event."""
    now = datetime.utcnow()
    status = _STATUS_MAP.get(state.get("action_taken"), "new")

    event = (Event.query
             .filter_by(source_ip=state.get("source_ip"), rule=state.get("rule"))
             .filter(Event.status != "dismissed")
             .order_by(Event.id.desc())
             .first())
    # session boundary: if the newest activity is far enough after the existing
    # event's last activity, treat it as a new attack session and open a fresh
    # event (keeps each event's first/last-seen window to one session).
    if event is not None and event.last_seen:
        new_ts = _parse_ts(state.get("last_seen"), now)
        from config.settings import settings as _s
        if (new_ts - event.last_seen).total_seconds() > _s.SESSION_GAP_HOURS * 3600:
            event = None
    if event is None:
        event = Event(
            source_ip=state.get("source_ip"),
            rule=state.get("rule"),
            first_seen=_parse_ts(state.get("first_seen"), now),
            ingested_at=now,   # CyREN's own clock; set ONCE, never overwritten on merge
        )
        db.session.add(event)

    event.dest_ip = state.get("dest_ip")
    event.attack_type = state.get("attack_type")
    event.log_count = max(event.log_count or 0, state.get("log_count", 0))
    event.confidence = state.get("confidence")
    event.risk = state.get("risk")
    event.status = status
    # whitelisted source: logged, and marked so tickets / alerts / training skip it
    if state.get("action_taken") == "whitelisted":
        event.suppress_reason = "whitelist"
    elif event.suppress_reason == "whitelist":
        event.suppress_reason = None
    event.mitre_techniques = state.get("mitre_techniques")
    event.llm_summary = state.get("llm_summary")
    event.raw_log_sample = (state.get("raw_logs") or [])[:20]
    event.threat_intel = state.get("threat_intel")
    event.asset_info = state.get("asset")
    event.vuln_info = state.get("vulnerability")
    event.last_seen = _parse_ts(state.get("last_seen"), now)

    # the aggregate's window must read start -> end; raw alert ordering can put
    # them the wrong way round, so normalise so first_seen is always the earliest.
    if event.first_seen and event.last_seen and event.first_seen > event.last_seen:
        event.first_seen, event.last_seen = event.last_seen, event.first_seen

    if state.get("is_multistage"):
        event.chain = _upsert_chain(state, now)

    db.session.flush()   # assign event.id before the rows below reference it

    if state.get("blocked"):
        already = BlockedIP.query.filter_by(ip=event.source_ip, active=True).first()
        if already is None:
            db.session.add(BlockedIP(ip=event.source_ip, attack_type=event.attack_type,
                                     blocked_by="auto", event_id=event.id))
            # audit trail: auto-containment must show in the event/case "Response
            # History" and the PDF response log too (matched by _response_log via
            # the leading "'<ip>'" — keep that exact shape)
            db.session.add(AuditLog(
                user_id=None, action="ip_blocked",
                detail=f"'{event.source_ip}' - reason: auto-contained "
                       f"({event.attack_type or 'threat'}, event #{event.id})"))

    if state.get("report_path"):
        db.session.add(Report(
            event_id=event.id,
            title=f"{event.attack_type} from {event.source_ip}",
            risk=event.risk,
            resolution="auto_blocked" if state.get("blocked") else "logged",
            file_path=state.get("report_path"),
        ))

    db.session.commit()
    return event
