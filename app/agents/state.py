"""
The shared state object that flows through the LangGraph pipeline.

Each agent reads from and writes to this dictionary-like state, so by the time
it reaches the end of the graph it holds the full picture of one event:
the triage verdict, the investigation, the correlation, and the response taken.
"""
from typing import TypedDict, Optional


class AgentState(TypedDict, total=False):
    # ---- Raw input (from ELK, already aggregated by source IP + rule) ----
    source_ip: str
    dest_ip: str
    rule: str
    log_count: int
    raw_logs: list          # list[str]
    severity: str           # highest Kibana alert severity in the aggregate
    risk_score: float       # highest Kibana alert risk score in the aggregate
    first_seen: str         # ISO timestamp of the oldest raw alert
    last_seen: str          # ISO timestamp of the newest raw alert

    # ---- Triage agent output ----
    attack_type: str
    confidence: float       # 0.0 - 1.0
    risk: str               # "high" | "uncertain" | "low"

    # ---- Investigation agent output ----
    mitre_techniques: list  # ["T1190 Exploit Public-Facing Application", ...]
    llm_summary: dict       # {"what_happened", "what_could_go_wrong", "what_should_be_done", "urgency"}

    # ---- Enrichment (threat intel / asset / vulnerability) ----
    threat_intel: dict      # {scope, known_bad, score, sources, detail}
    asset: dict             # {name, criticality, owner, risk_adjustment, ...}
    vulnerability: dict     # {vuln_count, exploitable, matching_cves, ...}

    # ---- Correlation agent output ----
    chain_id: Optional[int]
    is_multistage: bool
    chain_stages: list      # ordered [{attack_type, phase, timestamp}, ...]
    chain_risk: str         # "CRITICAL" | "HIGH" | "MEDIUM"
    chain_assessment: str   # human-readable summary of the chain
    predicted_next: Optional[str]   # likely next kill-chain stage

    # ---- Response agent output ----
    action_taken: str       # "blocked" | "awaiting_approval" | "logged"
    blocked: bool
    report_path: Optional[str]
