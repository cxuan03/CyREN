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

from app.models.db import db, Event, AttackChain, BlockedIP, Report

_STATUS_MAP = {"blocked": "blocked", "awaiting_approval": "awaiting", "logged": "logged"}


def _parse_ts(value, default=None):
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            pass
    return default or datetime.utcnow()


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
    event.mitre_techniques = state.get("mitre_techniques")
    event.llm_summary = state.get("llm_summary")
    event.raw_log_sample = (state.get("raw_logs") or [])[:20]
    event.threat_intel = state.get("threat_intel")
    event.asset_info = state.get("asset")
    event.vuln_info = state.get("vulnerability")
    event.last_seen = _parse_ts(state.get("last_seen"), now)

    if state.get("is_multistage"):
        event.chain = _upsert_chain(state, now)

    db.session.flush()   # assign event.id before the rows below reference it

    if state.get("blocked"):
        already = BlockedIP.query.filter_by(ip=event.source_ip, active=True).first()
        if already is None:
            db.session.add(BlockedIP(ip=event.source_ip, attack_type=event.attack_type,
                                     blocked_by="auto", event_id=event.id))

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
