"""Agent-level tests that go beyond tests/test_pipeline.py.

TC-U08a: chain risk is the higher of depth (distinct kill-chain phases) and
         severity (the most severe live event).
TC-U08b: a false-positive verdict recomputes the chain at once, and Undo
         restores it (runs against a throw-away SQLite file).
"""
import os
import tempfile
from datetime import datetime

# a private database for the app-context test, chosen BEFORE the app is imported
_TMP_DB = os.path.join(tempfile.gettempdir(), "cyren_test_agents.db")
os.environ["DATABASE_URL"] = "sqlite:///" + _TMP_DB.replace("\\", "/")


def test_chain_risk_takes_higher_of_depth_and_severity():
    from app.agents.correlation import compute_chain

    one_stage_high = [{"attack_type": "SSH Brute Force", "timestamp": "2026-09-01T10:00:00", "risk": "high"}]
    assert compute_chain(one_stage_high)["chain_risk"] == "HIGH"          # severity lifts a 1-phase chain

    same_phase_uncertain = [
        {"attack_type": "SQL Injection", "timestamp": "2026-09-01T10:00:00", "risk": "uncertain"},
        {"attack_type": "Cross-Site Scripting", "timestamp": "2026-09-01T10:05:00", "risk": "uncertain"},
    ]
    c = compute_chain(same_phase_uncertain)
    assert c["phase_count"] == 1 and len(c["chain_stages"]) == 2           # two attack types, one phase
    assert c["chain_risk"] == "MEDIUM"

    three_phases_low = [
        {"attack_type": "Port Scanning", "timestamp": "2026-09-01T10:00:00", "risk": "uncertain"},
        {"attack_type": "SSH Brute Force", "timestamp": "2026-09-01T11:00:00", "risk": "uncertain"},
        {"attack_type": "SQL Injection", "timestamp": "2026-09-01T12:00:00", "risk": "uncertain"},
    ]
    assert compute_chain(three_phases_low)["chain_risk"] == "CRITICAL"    # depth alone reaches CRITICAL

    empty = compute_chain([])
    assert empty["chain_risk"] is None and empty["chain_stages"] == [] and empty["predicted_next"] is None


def test_chain_recomputed_on_false_positive_and_undo():
    if os.path.exists(_TMP_DB):
        os.remove(_TMP_DB)
    from app import create_app
    from app.models.db import db, AttackChain, Event
    from app.api.routes import _recompute_chain

    app = create_app()
    with app.app_context():
        now = datetime.utcnow()
        chain = AttackChain(source_ip="10.9.9.9", highest_risk="HIGH", stage_count=2, first_seen=now, last_seen=now,
                            stages=[{"attack_type": "SSH Brute Force", "phase": "Credential Access", "timestamp": ""},
                                    {"attack_type": "SQL Injection", "phase": "Initial Access", "timestamp": ""}])
        db.session.add(chain); db.session.flush()
        bf = Event(source_ip="10.9.9.9", attack_type="SSH Brute Force", risk="high", status="blocked",
                   chain_id=chain.id, first_seen=now, last_seen=now)
        sqli = Event(source_ip="10.9.9.9", attack_type="SQL Injection", risk="high", status="blocked",
                     chain_id=chain.id, first_seen=now, last_seen=now)
        db.session.add_all([bf, sqli]); db.session.commit()

        sqli.status = "dismissed"; _recompute_chain(chain.id); db.session.commit()
        assert chain.stage_count == 1
        assert [s["attack_type"] for s in chain.stages] == ["SSH Brute Force"]
        assert chain.highest_risk == "HIGH"                                  # one phase, but the event is high
        assert chain.predicted_next.startswith("Initial Access")

        bf.status = "dismissed"; _recompute_chain(chain.id); db.session.commit()
        assert chain.stage_count == 0 and chain.stages == [] and chain.highest_risk is None

        sqli.status = "blocked"; bf.status = "blocked"; _recompute_chain(chain.id); db.session.commit()
        assert chain.stage_count == 2 and chain.highest_risk == "HIGH"


def test_rescore_contains_awaiting_events_raised_to_high():
    """TC-S17: a re-score (threshold or asset criticality change) that lifts an
    awaiting event to HIGH contains it under 'standard', skips whitelisted
    sources, and leaves it alone under 'advisory'."""
    from app import create_app
    from app.models.db import db, Event, BlockedIP, Setting, User, Whitelist
    from app.enrichment.asset_assessment import Asset
    app = create_app()
    with app.app_context(), app.test_request_context():
        from flask_login import login_user
        from app.api import routes as R
        u = User.query.first() or User(username="tester", full_name="Test Manager", email="t@example.com", role="manager", is_active=True)
        if u.id is None:
            u.set_password("Passw0rd!x"); db.session.add(u); db.session.commit()
        login_user(u)
        row = Setting.query.filter_by(key="automation_level").first()
        if row is None:
            row = Setting(key="automation_level", value="standard"); db.session.add(row)
        row.value = "standard"
        if not Asset.query.filter_by(ip="10.7.7.7").first():
            db.session.add(Asset(ip="10.7.7.7", name="CRIT-BOX", criticality="high"))
        e = Event(source_ip="10.8.8.8", dest_ip="10.7.7.7", attack_type="SQL Injection",
                  confidence=0.60, risk="uncertain", status="awaiting")
        db.session.add(e); db.session.commit()

        assert R._rescore_events(0.85, 0.40) >= 1          # 0.60 + critical-asset bump -> high
        assert e.id in [x.id for x in R._rescore_events.raised]
        assert R._contain_after_rescore("test") == 1
        assert e.status == "blocked" and BlockedIP.query.filter_by(ip="10.8.8.8", active=True).count() == 1

        # whitelisted source: label changes, nothing is blocked
        e.status = "awaiting"; e.risk = "uncertain"
        for b in BlockedIP.query.filter_by(ip="10.8.8.8").all(): db.session.delete(b)
        db.session.add(Whitelist(ip="10.8.8.8", reason="test")); db.session.commit()
        R._rescore_events(0.85, 0.40)
        assert R._contain_after_rescore("test") == 0 and e.status == "awaiting"

        # advisory: a human approves every block
        for w in Whitelist.query.filter_by(ip="10.8.8.8").all(): db.session.delete(w)
        e.status = "awaiting"; e.risk = "uncertain"; row.value = "advisory"; db.session.commit()
        R._rescore_events(0.85, 0.40)
        assert R._contain_after_rescore("test") == 0 and e.status == "awaiting"
