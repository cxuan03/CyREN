"""
CorrelationAgent
================
Role in the pipeline: the third agent. It decides whether this event is part of
a larger multi-stage attack from the same source, by linking it to earlier
events from the same IP and reconstructing the sequence as a graph with
NetworkX.

Output written to state:
    chain_id         : id of the attack chain this event belongs to (or None,
                       assigned by the persistence layer when the event is saved)
    is_multistage    : True if the chain now has more than one stage
    chain_stages     : ordered [{attack_type, phase, timestamp}, ...]
    chain_risk       : CRITICAL (>=3 phases) | HIGH (2) | MEDIUM (1)
    chain_assessment : human-readable summary
    predicted_next   : the next kill-chain stage to watch for (or None)
"""
from datetime import datetime, timedelta

from app.agents.state import AgentState

try:
    import networkx as nx
except ImportError:
    nx = None

# how far back to look when correlating (a slow attacker may span months)
CORRELATION_WINDOW_DAYS = 180

# kill-chain ordering + phase names (as validated in the FYP1 prototype)
KILL_CHAIN = {
    "Port Scanning":        (0, "Reconnaissance"),
    "SSH Brute Force":      (1, "Credential Access"),
    "SQL Injection":        (2, "Initial Access"),
    "Cross-Site Scripting": (2, "Initial Access"),
    "Command Injection":    (3, "Execution"),
    "File Inclusion":       (3, "Execution"),
    "Web Shell":            (4, "Persistence"),
}

# representative next stage for each kill-chain order, used for prediction
_NEXT_STAGE = {
    0: "Credential Access (e.g. SSH brute force)",
    1: "Initial Access (e.g. SQL injection / XSS)",
    2: "Execution (e.g. command injection / file inclusion)",
    3: "Persistence (e.g. web shell)",
}


def _order(attack_type: str) -> int:
    return KILL_CHAIN.get(attack_type, (99, "Unknown"))[0]


def _phase(attack_type: str) -> str:
    return KILL_CHAIN.get(attack_type, (99, "Unknown"))[1]


class CorrelationAgent:
    def __init__(self, event_repo=None):
        # event_repo lets tests inject a fake DB layer; by default the agent
        # queries the Event table directly (requires an app context).
        self.event_repo = event_repo

    def _fetch_prior_events(self, source_ip: str) -> list:
        """Prior events from this IP within the correlation window."""
        since = datetime.utcnow() - timedelta(days=CORRELATION_WINDOW_DAYS)
        if self.event_repo is not None:
            return self.event_repo.get_events_by_ip(source_ip, since=since)
        try:
            from app.models.db import Event
            rows = (Event.query
                    .filter(Event.source_ip == source_ip,
                            Event.last_seen >= since,
                            Event.status != "dismissed")
                    .all())
            return [{"attack_type": r.attack_type,
                     "timestamp": r.last_seen.isoformat() if r.last_seen else ""}
                    for r in rows]
        except Exception:
            return []   # no DB / no app context (e.g. unit tests)

    def _order_stages(self, events: list) -> list:
        return sorted(
            events,
            key=lambda e: (_order(e.get("attack_type")), e.get("timestamp") or ""),
        )

    def _build_graph(self, stages: list):
        if nx is None:
            return None
        g = nx.DiGraph()
        for i, stage in enumerate(stages):
            g.add_node(i, **stage)
            if i > 0:
                g.add_edge(i - 1, i)
        return g

    def _assess(self, phase_count: int) -> str:
        if phase_count >= 3:
            return ("Multi-stage attack detected. Attacker progressed through "
                    "multiple kill chain phases, indicating a sophisticated and "
                    "targeted attack campaign.")
        if phase_count >= 2:
            return ("Attack chain detected. Attacker used multiple techniques, "
                    "suggesting an active intrusion attempt.")
        return "Single-phase attack detected. Limited attack scope observed."

    # ------------------------------------------------------------------
    def run(self, state: AgentState) -> AgentState:
        source_ip = state.get("source_ip")
        prior = self._fetch_prior_events(source_ip)

        # include the current event as the newest stage
        current = {"attack_type": state.get("attack_type"),
                   "timestamp": state.get("last_seen") or datetime.utcnow().isoformat()}
        # de-duplicate: one stage per attack type
        by_type = {}
        for e in self._order_stages(prior + [current]):
            by_type.setdefault(e.get("attack_type"), e)
        stages = list(by_type.values())

        chain_stages = [{"attack_type": s.get("attack_type"),
                         "phase": _phase(s.get("attack_type")),
                         "timestamp": s.get("timestamp", "")}
                        for s in stages]
        phases = {s["phase"] for s in chain_stages}

        graph = self._build_graph(chain_stages)   # noqa: F841 (used when persisting)

        max_order = max((_order(s.get("attack_type")) for s in stages), default=99)
        state["chain_stages"] = chain_stages
        state["chain_risk"] = ("CRITICAL" if len(phases) >= 3
                               else "HIGH" if len(phases) >= 2 else "MEDIUM")
        state["chain_assessment"] = self._assess(len(phases))
        state["predicted_next"] = _NEXT_STAGE.get(max_order)
        state["is_multistage"] = len(chain_stages) > 1
        # chain_id is assigned by the persistence layer when the event is saved
        state["chain_id"] = None
        return state


_correlation = CorrelationAgent()
def correlation_node(state: AgentState) -> AgentState:
    return _correlation.run(state)
