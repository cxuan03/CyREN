"""
Enrichment layer for CyREN.

These three modules add the context that turns a raw classification into a
prioritised decision:

    threat_intel     -> who is attacking (IP reputation)
    asset_assessment -> what is being attacked (asset criticality)
    vuln_assessment  -> whether the attack can succeed (matching CVE)

Combined risk intuition:
    danger = attack severity
             x asset criticality
             x target exploitability
             x attacker reputation

The agents call these; they are not themselves agents, so the four-agent
architecture from Chapter 1 is unchanged. They enrich the pipeline rather than
extend it.
"""
from app.enrichment.threat_intel import threat_intel
from app.enrichment.asset_assessment import asset_assessment
from app.enrichment.vuln_assessment import vuln_assessment

__all__ = ["threat_intel", "asset_assessment", "vuln_assessment", "enrich_event"]


def _attack_type_from_rule(rule: str) -> str:
    """
    Derive a provisional attack type from the detection rule so vulnerability
    matching can run before the classifier assigns the final type. Triage will
    confirm the attack type afterwards.
    """
    rule = (rule or "").lower()
    for key, name in [("sqli", "SQL Injection"), ("xss", "Cross-Site Scripting"),
                      ("ssh", "SSH Brute Force"), ("cmd", "Command Injection"),
                      ("scan", "Port Scanning")]:
        if key in rule:
            return name
    return "Unclassified"


def enrich_event(state: dict) -> dict:
    """
    Run all three enrichments for one event and attach the results to state.
    Runs before Triage so risk adjustment and the LLM analysis both have the
    full picture (who is attacking, what is being attacked, whether it is
    vulnerable).
    """
    source_ip = state.get("source_ip")
    dest_ip = state.get("dest_ip")
    attack_type = state.get("attack_type") or _attack_type_from_rule(state.get("rule", ""))

    state["threat_intel"] = threat_intel.lookup(source_ip) if source_ip else {}
    state["asset"] = asset_assessment.lookup(dest_ip) if dest_ip else {}
    state["vulnerability"] = vuln_assessment.assess(dest_ip, attack_type) if dest_ip else {}
    return state
