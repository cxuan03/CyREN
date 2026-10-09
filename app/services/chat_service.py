"""
SOC assistant chatbot: answers an analyst's natural-language question grounded
in CyREN's real data.

The flow is retrieval-augmented, not free hallucination: the question is scanned
for entities (IP addresses, event IDs, ticket/case IDs); the matching real
Event / Ticket / AttackChain / BlockedIP records are pulled from the database
and formatted as context (plus computed correlation facts when several
entities are named); and the
local LLM (via InvestigationAgent) is instructed to answer ONLY from that context
and to say when it does not know. Nothing is invented - every fact the model is
given comes from a real row, and the sources are returned for transparency.
"""
import itertools
import re
from collections import Counter
from datetime import datetime

from app.models.db import (db, Event, AttackChain, BlockedIP, Ticket,
                           TicketActivity)
from app.enrichment.threat_intel import threat_intel

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EID_RE = re.compile(r"(?:#|\bevent\s+)(\d+)", re.I)
# "ticket 201", "tickets 188 and 201", "T-201", "case 7" — lists included
_NUM_LIST = r"(\d+(?:\s*(?:,|and|&|和|跟|与)\s*#?\d+)*)"
_TID_LIST_RE = re.compile(r"\b(?:tickets?|cases?)\s+#?" + _NUM_LIST, re.I)
_T_RE = re.compile(r"\bT-(\d+)\b", re.I)
_EID_LIST_RE = re.compile(r"\bevents?\s+#?" + _NUM_LIST, re.I)


def _num_list(list_re, text):
    out = []
    for m in list_re.findall(text):
        out += [int(x) for x in re.findall(r"\d+", m)]
    return out

SYSTEM = (
    "You are CyREN's SOC assistant. Answer the analyst's question using ONLY the "
    "CyREN DATA provided below. If the data does not contain the answer, say you "
    "do not have that information - never invent hosts, IPs, times, events, MITRE "
    "techniques or numbers. Be concise and specific, and cite ticket IDs (T-N), "
    "event IDs (#N) and IP addresses drawn from the data. When asked whether "
    "things are related or part of one attack, base your judgement on the "
    "'Correlation facts' lines (same source IP / same attack chain / time "
    "overlap) and say which facts support it."
)


def _dt(dt):
    return dt.strftime("%d-%m-%Y %H:%M") if dt else "?"


def _event_line(e):
    conf = round((e.confidence or 0) * 100)
    mitre = ", ".join(e.mitre_techniques or []) or "n/a"
    return (f"- Event #{e.id}: {e.attack_type or 'event'} from {e.source_ip}, "
            f"risk={e.risk}, status={e.status}, confidence={conf}%, "
            f"logs={e.log_count}, seen {_dt(e.first_seen)}..{_dt(e.last_seen)}, "
            f"MITRE={mitre}")


def _ticket_lines(t):
    """A ticket's real facts + its attached events + its worked timeline."""
    out = [(f"- Ticket T-{t.id}: '{t.title or 'case'}', status={t.status}, "
            f"risk={t.risk()}, source_ip={t.source_ip or 'none'}, "
            f"raised_by={t.raised_by}, opened {_dt(t.created_at)}"
            + (f", closed {_dt(t.closed_at)}" if t.closed_at else " (still open)"))]
    for e in t.events:
        out.append("  " + _event_line(e))
    if not t.events:
        out.append("  (no events attached to this ticket)")
    acts = (TicketActivity.query.filter_by(ticket_id=t.id)
            .order_by(TicketActivity.created_at).limit(10).all())
    if acts:
        out.append(f"  Timeline of ticket T-{t.id} (who did what, when):")
        for a in acts:
            out.append(f"    {_dt(a.created_at)} — {a.text or '-'}")
    return out


def _facts_group(label, events, extra_ips=(), life=None):
    """Comparable facts for one entity (a ticket's events, or one event).
    `life` is a ticket's (opened_at, closed_at-or-None) working lifecycle."""
    times = [x for e in events for x in (e.first_seen, e.last_seen) if x]
    return {
        "label": label,
        "ips": {e.source_ip for e in events if e.source_ip} | set(x for x in extra_ips if x),
        "chains": {e.chain_id for e in events if e.chain_id},
        "types": {e.attack_type for e in events if e.attack_type},
        "window": (min(times), max(times)) if times else None,
        "life": life,
    }


def _gap_text(seconds):
    seconds = abs(seconds)
    if seconds < 3600:
        return f"{int(seconds // 60)} minute(s)"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} hour(s)"
    return f"{seconds / 86400:.1f} day(s)"


def _correlation_lines(groups):
    """Deterministic pairwise correlation FACTS from the stored rows — same
    source? same chain? overlapping time? — so the LLM reasons from real data
    instead of guessing whether two tickets/events are one attack."""
    out = ["Correlation facts (computed from the stored data):"]
    for a, b in list(itertools.combinations(groups, 2))[:3]:
        pair = f"{a['label']} vs {b['label']}"
        shared_ip = a["ips"] & b["ips"]
        if shared_ip:
            out.append(f"- {pair}: SAME source IP ({', '.join(sorted(shared_ip))}).")
        else:
            out.append(f"- {pair}: different source IPs "
                       f"({', '.join(sorted(a['ips'])) or 'none'} vs "
                       f"{', '.join(sorted(b['ips'])) or 'none'}).")
        shared_ch = a["chains"] & b["chains"]
        if shared_ch:
            out.append(f"- {pair}: both belong to attack chain "
                       f"#C-{sorted(shared_ch)[0]} — part of the SAME multi-stage attack.")
        elif a["chains"] and b["chains"]:
            out.append(f"- {pair}: they sit on DIFFERENT attack chains.")
        else:
            out.append(f"- {pair}: no shared attack chain recorded.")
        if a["window"] and b["window"]:
            if a["window"][0] <= b["window"][1] and b["window"][0] <= a["window"][1]:
                out.append(f"- {pair}: their ATTACK activity windows OVERLAP in time.")
            else:
                gap = (max(a["window"][0], b["window"][0])
                       - min(a["window"][1], b["window"][1])).total_seconds()
                out.append(f"- {pair}: attack activity windows are {_gap_text(gap)} apart.")
        # ticket LIFECYCLES: were both cases being worked at the same time,
        # or was one closed before the other was even opened?
        if a["life"] and b["life"]:
            now = datetime.utcnow()
            a0, a1 = a["life"][0], a["life"][1] or now
            b0, b1 = b["life"][0], b["life"][1] or now
            if a0 and b0:
                if a0 <= b1 and b0 <= a1:
                    out.append(f"- {pair}: both tickets were OPEN at the same time "
                               f"({a['label']}: {_dt(a['life'][0])}..{_dt(a['life'][1]) if a['life'][1] else 'still open'}; "
                               f"{b['label']}: {_dt(b['life'][0])}..{_dt(b['life'][1]) if b['life'][1] else 'still open'}).")
                else:
                    first, second = (a, b) if a1 <= b0 else (b, a)
                    out.append(f"- {pair}: {first['label']} was CLOSED before "
                               f"{second['label']} was opened — they were never worked simultaneously.")
    return out


def build_context(scan_text: str):
    """Return (context, sources, focus_event_ids) built from real DB rows for the
    entities found in scan_text (the current question plus recent turns, so a
    follow-up like 'what did it do?' still resolves the earlier IP/event)."""
    ips = list(dict.fromkeys(_IP_RE.findall(scan_text)))
    eids = list(dict.fromkeys([int(x) for x in _EID_RE.findall(scan_text)]
                              + _num_list(_EID_LIST_RE, scan_text)))
    tids = list(dict.fromkeys(_num_list(_TID_LIST_RE, scan_text)
                              + [int(x) for x in _T_RE.findall(scan_text)]))
    lines, sources = [], []
    focus_ids = []   # every event the question resolved, for the timeline panel
    groups = []      # comparable fact-sets for the correlation block

    def _focus(eid):
        if eid and eid not in focus_ids:
            focus_ids.append(eid)

    for tid in tids:
        t = db.session.get(Ticket, tid)
        if t:
            lines += _ticket_lines(t)
            sources.append(f"ticket T-{t.id}")
            groups.append(_facts_group(f"ticket T-{t.id}", list(t.events),
                                       extra_ips=[t.source_ip],
                                       life=(t.created_at, t.closed_at)))
            for e in t.events:
                _focus(e.id)
        else:
            # honest, and helpful about the common id mix-up: the number may
            # actually be an EVENT id, not a ticket id
            e2 = db.session.get(Event, tid)
            if e2 is not None:
                lines.append(f"There is NO ticket T-{tid} — but {tid} matches an "
                             f"EVENT id (shown below):")
                if tid not in eids:
                    eids.append(tid)
            else:
                lines.append(f"No ticket or event with id {tid} exists in CyREN.")

    for eid in eids:
        e = db.session.get(Event, eid)
        if e:
            lines.append(_event_line(e))
            summ = e.llm_summary or {}
            if summ.get("what_happened"):
                lines.append(f"  analysis: {summ.get('what_happened')}")
            sources.append(f"event #{e.id}")
            groups.append(_facts_group(f"event #{e.id}", [e]))
            _focus(e.id)
        else:
            lines.append(f"No event #{eid} exists in CyREN.")

    for ip in ips:
        evs = (Event.query.filter_by(source_ip=ip)
               .order_by(Event.last_seen.desc()).limit(12).all())
        if evs:
            lines.append(f"Source {ip} has {len(evs)} event(s):")
            lines += [_event_line(e) for e in evs]
            sources.append(ip)
            # the IP's most recent few events feed the timeline panel too
            for e in evs[:4]:
                _focus(e.id)
        else:
            lines.append(f"Source {ip}: no events on record.")
        b = BlockedIP.query.filter_by(ip=ip, active=True).first()
        lines.append(f"Firewall: {ip} is "
                     + (f"BLOCKED ({b.blocked_by or 'manual'})" if b else "NOT currently blocked")
                     + ".")
        ch = (AttackChain.query.filter_by(source_ip=ip)
              .order_by(AttackChain.id.desc()).first())
        if ch and ch.stages:
            stages = " -> ".join(str(s.get("attack_type")) for s in ch.stages)
            lines.append(f"Attack chain for {ip}: {ch.stage_count} stages, "
                         f"highest risk {ch.highest_risk}: {stages}")
        # external threat-intel reputation, honest about private lab addresses
        try:
            ti = threat_intel.lookup(ip)
            if ti.get("known_bad"):
                lines.append(f"Threat intel for {ip}: FLAGGED known-bad "
                             f"(score {ti.get('score')}/100; sources: "
                             f"{', '.join(ti.get('sources') or []) or 'n/a'}).")
            elif ti.get("scope") == "public":
                lines.append(f"Threat intel for {ip}: public IP, reputation score "
                             f"{ti.get('score')}/100 ({', '.join(ti.get('sources') or ['none'])}).")
            else:
                lines.append(f"Threat intel for {ip}: private/internal address - no public "
                             f"reputation applies; not in the local bad-IP feed.")
        except Exception:
            pass

    if len(groups) >= 2:
        lines += _correlation_lines(groups)

    if not ips and not eids and not tids:
        # no specific entity: give a real situational overview
        all_events = Event.query.all()
        risk = Counter(e.risk for e in all_events)
        awaiting = Event.query.filter_by(status="awaiting").count()
        blocked = BlockedIP.query.filter_by(active=True).count()
        lines.append(
            f"System overview: {len(all_events)} events total. Risk tiers: "
            f"high={risk.get('high', 0)} (auto-blocked), "
            f"uncertain={risk.get('uncertain', 0)}, low={risk.get('low', 0)} (logged only). "
            f"{awaiting} event(s) are awaiting a human decision - these are the ones "
            f"needing attention. {blocked} IP(s) are currently blocked at the firewall.")
        hi = (Event.query.filter_by(risk="high")
              .order_by(Event.last_seen.desc()).limit(8).all())
        if hi:
            lines.append("Most recent high-risk events:")
            lines += [_event_line(e) for e in hi]
        sources.append("system overview")

    context = "\n".join(lines) if lines else "(no matching CyREN data found)"
    return context, sources, focus_ids


def answer_question(question: str, history=None) -> dict:
    """Answer one question with multi-turn context. `history` is a list of
    {role, text}. Returns {ok, answer|error, sources, focus_event_id}."""
    from app.agents.investigation import _investigation
    history = history or []
    recent = [h for h in history if (h.get("text") or "").strip()][-6:]
    # entity extraction over recent turns + this question, so pronouns resolve
    scan = " ".join(h.get("text", "") for h in recent) + " " + question
    context, sources, focus_ids = build_context(scan)

    messages = [{"role": "system", "content": SYSTEM}]
    for h in recent:
        role = "assistant" if h.get("role") in ("bot", "assistant") else "user"
        messages.append({"role": role, "content": (h.get("text") or "")[:1500]})
    messages.append({"role": "user",
                     "content": f"CyREN DATA:\n{context}\n\nQUESTION: {question}"})

    text, err = _investigation.chat_messages(messages, max_tokens=600)
    # single id kept for back-compat; the list drives the multi-event timeline
    focus = focus_ids[0] if focus_ids else None
    if err:
        return {"ok": False, "error": err, "sources": sources,
                "focus_event_id": focus, "focus_event_ids": focus_ids}
    return {"ok": True, "answer": text, "sources": sources,
            "focus_event_id": focus, "focus_event_ids": focus_ids}
