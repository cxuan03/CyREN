"""Ticket auto-raise — turns detections into cases (the approved Case model).

Rules:
  * one attack chain                          -> one ticket (all chain events attached)
  * high-risk events with no chain/ticket     -> one ticket per source IP
  * uncertain (awaiting) events, no ticket    -> one queue ticket per source IP
Low-risk logged noise never raises a ticket.

Titles and descriptions are built from the investigation output already stored
on the events (the LLM summaries written at detection time) — no extra LLM
calls inside the polling loop.
"""
from __future__ import annotations

from datetime import timedelta

from app.models.db import (db, AttackChain, Event, Notification, Ticket,
                           TicketActivity, User)


def _summary_text(e: Event) -> str:
    s = e.llm_summary or {}
    if isinstance(s, dict):
        return (s.get("what_happened") or s.get("summary") or "").strip()
    return str(s).strip()


def _title_for(events, chain=None) -> str:
    types = []
    for e in sorted(events, key=lambda x: {"high": 0, "uncertain": 1, "low": 2}.get(x.risk or "low", 3)):
        t = e.attack_type or "Unclassified"
        if t not in types:
            types.append(t)
    if chain is not None and (chain.stage_count or len(types)) >= 3:
        return "Multi-stage intrusion"
    if not types:
        return "Suspicious activity"
    if len(types) == 1:
        return types[0]
    if len(types) == 2:
        return types[0] + " + " + types[1]
    return "Multi-stage intrusion"


def _description_for(events, chain=None) -> str:
    # Prefer the LLM summary of the highest-risk event; fall back to a factual line.
    for e in sorted(events, key=lambda x: {"high": 0, "uncertain": 1, "low": 2}.get(x.risk or "low", 3)):
        txt = _summary_text(e)
        if txt:
            return txt[:2000]
    types = ", ".join(sorted({e.attack_type or "Unclassified" for e in events}))
    n = len(events)
    base = f"{n} event group{'s' if n != 1 else ''} ({types})"
    if chain is not None and chain.predicted_next:
        base += f". Predicted next stage: {chain.predicted_next}."
    return base[:2000]


def _ticketed_event_ids():
    rows = db.session.execute(db.text("SELECT event_id FROM ticket_events")).fetchall()
    return {r[0] for r in rows}


def _attack_window(events, chain=None):
    """The real attack span from the logs (earliest first_seen). This is the
    INCIDENT time — kept separate from the ticket's OPEN time, which is when a
    human/CyREN actually raised the case (real clock)."""
    times = [e.first_seen for e in events if e.first_seen]
    if chain is not None and chain.first_seen:
        times.append(chain.first_seen)
    return min(times) if times else None


def _act(ticket: Ticket, text: str):
    db.session.add(TicketActivity(ticket_id=ticket.id, user_id=None, text=text[:300]))


def _notify_all_raised(t: Ticket):
    """Every active user gets a bell notification when CyREN raises a ticket —
    new cases must be visible to the whole team, not just an assignee."""
    text = ("CyREN raised ticket T-%d (%s) — %s"
            % (t.id, t.risk(), (t.title or "")))[:300]
    for u in User.query.filter_by(is_active=True).all():
        db.session.add(Notification(user_id=u.id, kind="ticket_raised",
                                    ref_id=t.id, text=text))


def auto_raise() -> int:
    """Create tickets for anything actionable that has none yet. Idempotent."""
    created = 0

    # linkage self-heal: events that predate their chain (or were aggregated
    # separately) never got chain_id set, so the chain page showed fewer event
    # IDs than kill-chain stages. Backfill by source IP + time window.
    for chain in AttackChain.query.all():
        for e in Event.query.filter_by(source_ip=chain.source_ip, chain_id=None).all():
            t0 = e.first_seen or e.last_seen
            if t0 is None or chain.first_seen is None:
                e.chain_id = chain.id
                continue
            lo = chain.first_seen - timedelta(hours=6)
            hi = (chain.last_seen or chain.first_seen) + timedelta(hours=6)
            if lo <= t0 <= hi:
                e.chain_id = chain.id
    db.session.commit()

    taken = _ticketed_event_ids()

    # 1) chains -> ONE OPEN case per chain. A case still open keeps accumulating
    #    the attacker's new events; once the case is CLOSED, a fresh attack from
    #    the same attacker opens a NEW ticket (its own clean timeline) instead of
    #    being silently appended to the closed case. `taken` already covers every
    #    event in any ticket (open or closed), so a new ticket only picks up the
    #    events from this fresh burst.
    open_ticket_by_chain = {}
    for t in Ticket.query.filter(Ticket.chain_id.isnot(None),
                                 Ticket.status != "closed").all():
        open_ticket_by_chain.setdefault(t.chain_id, t)
    for chain in AttackChain.query.all():
        ct = open_ticket_by_chain.get(chain.id)
        if ct is not None:
            # open case: fold in this attacker's new events (respect detachments)
            excl = set(ct.excluded_event_ids or [])
            newly = [e for e in (chain.events or [])
                     if e.id not in taken and e.id not in excl
                     and e.suppress_reason != "whitelist"]   # whitelisted: recorded, never cased
            if newly:
                for e in newly:
                    ct.events.append(e)
                _act(ct, f"{len(newly)} new event(s) from this attacker added to the case")
            taken.update(e.id for e in chain.events or [])
            continue
        # no OPEN case: ticket only the events not already in a (now-closed)
        # ticket — that is this fresh burst
        events = [e for e in (chain.events or [])
                  if e.id not in taken and e.suppress_reason != "whitelist"]
        if not events:      # nothing actionable (or the whole chain is whitelisted)
            continue
        # created_at defaults to NOW (when the sweep actually opened the case);
        # the attack's own time lives on the events (first_seen/last_seen)
        t = Ticket(title=_title_for(events, chain), description=_description_for(events, chain),
                   source_ip=chain.source_ip, chain_id=chain.id, status="queue", raised_by="auto")
        t.events = events
        db.session.add(t)
        db.session.flush()
        _act(t, f"Auto-raised from attack chain #{chain.id} ({len(events)} events)")
        _notify_all_raised(t)
        taken.update(e.id for e in events)
        created += 1

    # 2) chainless actionable events -> ONE OPEN case per source IP, same rule:
    #    accumulate into an open case, open a new one once the old is closed.
    #    high risk always; uncertain only while awaiting a human decision
    open_ticket_by_ip = {}
    for t in Ticket.query.filter(Ticket.chain_id.is_(None),
                                 Ticket.status != "closed").all():
        if t.source_ip:
            open_ticket_by_ip.setdefault(t.source_ip, t)
    loose = (Event.query
             .filter(Event.chain_id.is_(None))
             .filter(db.or_(Event.suppress_reason.is_(None), Event.suppress_reason != "whitelist"))
             .filter(db.or_(Event.risk == "high",
                            db.and_(Event.risk == "uncertain", Event.status == "awaiting")))
             .all())
    by_ip: dict[str, list] = {}
    for e in loose:
        if e.id in taken:
            continue
        by_ip.setdefault(e.source_ip or "?", []).append(e)
    for ip, events in by_ip.items():
        ct = open_ticket_by_ip.get(ip)
        if ct is not None:
            excl = set(ct.excluded_event_ids or [])
            newly = [e for e in events if e.id not in excl]
            if newly:
                for e in newly:
                    ct.events.append(e)
                _act(ct, f"{len(newly)} new event(s) from this attacker added to the case")
            taken.update(e.id for e in events)
            continue
        t = Ticket(title=_title_for(events), description=_description_for(events),
                   source_ip=ip, status="queue", raised_by="auto")
        t.events = events
        db.session.add(t)
        db.session.flush()
        risk = t.risk()
        why = "new high-risk source" if risk == "high" else "uncertain events, needs human triage"
        _act(t, f"Auto-raised — {why}")
        _notify_all_raised(t)
        taken.update(e.id for e in events)
        created += 1

    # date self-heal: an EARLIER design backdated created_at to the attack time,
    # so a case opened on the 21st for a July log showed "opened July 18" and was
    # unfindable under today. A ticket cannot be worked before it exists, so its
    # first activity row (stamped with the real clock when it was raised) is the
    # true open time — pull created_at FORWARD to it when it was backdated.
    healed = 0
    for t in Ticket.query.all():
        first_act = (TicketActivity.query.filter_by(ticket_id=t.id)
                     .order_by(TicketActivity.created_at.asc()).first())
        if (first_act and first_act.created_at and t.created_at
                and (first_act.created_at - t.created_at).total_seconds() > 120):
            t.created_at = first_act.created_at
            healed += 1
    # invariant repair: queue means "up for grabs", so no assignee may linger
    # (covers tickets that entered that state before the rule existed)
    for t in Ticket.query.filter_by(status="queue").filter(Ticket.assignee_id.isnot(None)).all():
        t.assignee_id = None
        healed += 1

    if created or healed:
        db.session.commit()
    return created
