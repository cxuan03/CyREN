"""
Smoke tests for the multi-agent pipeline. Run: pytest

The routing tests pin the agents to placeholder mode (no model file) so they
keep asserting the tier-routing contract even after the real XGBoost model has
been trained -- the model's verdict on synthetic events is not what these
tests check.
"""
import sys, os

# Force placeholder mode BEFORE settings/agents are imported.
os.environ["XGBOOST_MODEL_PATH"] = "data/models/__missing__.json"
os.environ["RULE_MAP_PATH"] = "data/models/__missing__.json"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.agents.pipeline import run_pipeline
from app.agents.triage import TriageAgent


def _event(rule, log_count):
    return {"source_ip": "192.168.56.50", "dest_ip": "192.168.56.10",
            "rule": rule, "log_count": log_count, "raw_logs": ["sample log"]}


def test_high_volume_event_is_high_risk():
    state = run_pipeline(_event("sqli-union", 400))
    assert state["risk"] == "high"
    assert state["action_taken"] == "blocked"
    assert state["attack_type"] == "SQL Injection"


def test_low_volume_event_is_low_risk():
    state = run_pipeline(_event("port-scan", 5))
    assert state["risk"] == "low"
    assert state["action_taken"] == "logged"
    # low-risk events skip investigation, so no techniques are attached
    assert not state.get("mitre_techniques")


def test_mid_volume_event_needs_approval():
    state = run_pipeline(_event("ssh-auth-fail", 150))
    assert state["risk"] == "uncertain"
    assert state["action_taken"] == "awaiting_approval"
    assert state["blocked"] is False


def test_triage_feature_vector():
    """The feature vector must match the training layout:
    [rule_encoded, risk_score, severity_num, has_keyword, request_count]"""
    agent = TriageAgent()
    agent.rule_map = {"SQL Injection Detected": 1}
    features = agent._extract_features({
        "rule": "SQL Injection Detected",
        "risk_score": 73,
        "severity": "high",
        "log_count": 42,
        "raw_logs": ["GET /dvwa/?id=1 UNION SELECT user,password FROM users"],
    })
    assert features.shape == (1, 5)
    assert list(features[0]) == [1, 73, 3, 1, 42]


def test_attack_chain_detects_multistage():
    """Two prior stages + the current one span three kill-chain phases."""
    from app.agents.correlation import CorrelationAgent

    class FakeRepo:
        def get_events_by_ip(self, ip, since=None):
            return [
                {"attack_type": "Port Scanning", "timestamp": "2026-07-01T10:00:00"},
                {"attack_type": "SSH Brute Force", "timestamp": "2026-07-01T11:00:00"},
            ]

    agent = CorrelationAgent(event_repo=FakeRepo())
    state = agent.run({"source_ip": "192.168.56.104",
                       "attack_type": "SQL Injection"})
    assert state["is_multistage"] is True
    assert state["chain_risk"] == "CRITICAL"
    assert [s["phase"] for s in state["chain_stages"]] == \
        ["Reconnaissance", "Credential Access", "Initial Access"]
    assert "Execution" in state["predicted_next"]
