"""
TriageAgent
===========
Role in the pipeline: the first agent. It takes an aggregated event (many raw
logs already grouped by source IP + detection rule) and produces a confidence
score with the XGBoost classifier, then routes the event into one of three
tiers using the thresholds from settings.

    confidence >= HIGH_RISK_THRESHOLD  -> "high"       (auto response downstream)
    confidence <= LOW_RISK_THRESHOLD   -> "low"        (log only)
    otherwise                          -> "uncertain"  (human approval)

Feature vector (must match scripts/train_triage.py):
    [rule_encoded, risk_score, severity_num, has_keyword, request_count]

The model is trained with binary:logistic, so Booster.predict() returns the
true-positive probability directly; that is the confidence routed on. Until
the model file exists the agent falls back to a log-volume heuristic so the
skeleton stays runnable.
"""
import json
import os
import numpy as np

from config.settings import settings
from app.agents.state import AgentState

try:
    import xgboost as xgb
except ImportError:      # allows the skeleton to run before xgboost is installed
    xgb = None


# payload keywords that indicate a genuine attack string in the raw logs
# (same indicator set the FYP1 prototype validated)
ATTACK_KEYWORDS = [
    "union select", "or 1=1", "' or '", "<script", "onerror=",
    "whoami", "etc/passwd", "/bin/bash", "nmap", "masscan",
    "failed password", "authentication failure",
]

SEVERITY_NUM = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# must match the training columns in scripts/train_triage.py
FEATURE_NAMES = ["rule_encoded", "risk_score", "severity_num", "has_keyword", "request_count"]

# substring -> attack type; checked in order, so put the most specific first
ATTACK_TYPE_RULES = [
    ("sql injection", "SQL Injection"),
    ("sqli", "SQL Injection"),
    ("xss", "Cross-Site Scripting"),
    ("command injection", "Command Injection"),
    ("cmd", "Command Injection"),
    ("file inclusion", "File Inclusion"),
    ("lfi", "File Inclusion"),
    ("port scan", "Port Scanning"),
    ("scan", "Port Scanning"),
    ("brute force", "SSH Brute Force"),
    ("ssh", "SSH Brute Force"),
]


class TriageAgent:
    def __init__(self):
        self.model = None
        self.rule_map = {}
        self._load_model()

    def _load_model(self):
        path = settings.XGBOOST_MODEL_PATH
        if xgb is not None and os.path.exists(path):
            self.model = xgb.Booster()
            self.model.load_model(path)
        if os.path.exists(settings.RULE_MAP_PATH):
            try:
                with open(settings.RULE_MAP_PATH) as fh:
                    self.rule_map = json.load(fh)
            except (json.JSONDecodeError, OSError):
                self.rule_map = {}

    # ------------------------------------------------------------------
    def _extract_features(self, state: AgentState) -> np.ndarray:
        """Build the 5-feature vector the model was trained on."""
        rule_encoded = self.rule_map.get(state.get("rule", ""), 0)
        risk_score = float(state.get("risk_score", 0) or 0)
        severity_num = SEVERITY_NUM.get((state.get("severity") or "").lower(), 1)

        haystack = " ".join(state.get("raw_logs", [])).lower()
        has_keyword = 1 if any(kw in haystack for kw in ATTACK_KEYWORDS) else 0

        request_count = state.get("log_count", 0)

        return np.array(
            [[rule_encoded, risk_score, severity_num, has_keyword, request_count]],
            dtype=float,
        )

    def _classify_attack_type(self, state: AgentState) -> str:
        """Derive the attack type from the detection rule that fired."""
        rule = (state.get("rule") or "").lower()
        for key, name in ATTACK_TYPE_RULES:
            if key in rule:
                return name
        return "Unclassified"

    def _route(self, confidence: float) -> str:
        if confidence >= settings.HIGH_RISK_THRESHOLD:
            return "high"
        if confidence <= settings.LOW_RISK_THRESHOLD:
            return "low"
        return "uncertain"

    def _adjust_for_context(self, state: AgentState, risk: str) -> str:
        """
        Nudge the risk tier using enrichment signals available at triage time.
        A critical asset or a known-bad source escalates; nothing de-escalates
        an already-high verdict.

        The enrichment is optional here: if it has not run yet (e.g. asset
        table empty), the signals are neutral and risk is unchanged.
        """
        order = ["low", "uncertain", "high"]
        idx = order.index(risk)

        # asset criticality: read lightweight signal without a full lookup
        asset = state.get("asset") or {}
        idx += asset.get("risk_adjustment", 0)

        # known-bad source escalates by one tier
        ti = state.get("threat_intel") or {}
        if ti.get("known_bad"):
            idx += 1

        idx = max(0, min(len(order) - 1, idx))
        return order[idx]

    # ------------------------------------------------------------------
    def run(self, state: AgentState) -> AgentState:
        features = self._extract_features(state)

        if self.model is not None:
            dmatrix = xgb.DMatrix(features, feature_names=FEATURE_NAMES)
            confidence = float(self.model.predict(dmatrix)[0])
        else:
            # PLACEHOLDER verdict so the pipeline works before the model exists.
            # Simple heuristic on log volume; replace once the model is trained.
            lc = state.get("log_count", 0)
            confidence = min(0.99, 0.30 + lc / 500.0)

        state["confidence"] = round(confidence, 2)
        state["attack_type"] = self._classify_attack_type(state)
        base_risk = self._route(confidence)
        state["risk"] = self._adjust_for_context(state, base_risk)
        return state


# LangGraph node wrapper
_triage = TriageAgent()
def triage_node(state: AgentState) -> AgentState:
    return _triage.run(state)
