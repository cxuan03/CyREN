"""
import os
Seed the database with default users and a little demo data so the dashboard
has something to show on first run.

    python scripts/seed.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta
from app import create_app
from app.models.db import db, User, Event, AttackChain, BlockedIP, Report


def seed():
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()

        # ---- users ----
        manager = User(username="manager01", full_name="Lim Hui Ying",
                       email="manager@company.com", role="manager")
        manager.set_password("Manager@2026")
        analyst = User(username="analyst01", full_name="Chong Mei San",
                       email="analyst@company.com", role="analyst")
        analyst.set_password("Analyst@2026")
        db.session.add_all([manager, analyst])

        # ---- a high-risk blocked event ----
        e1 = Event(source_ip="192.168.56.102", dest_ip="192.168.56.10",
                   attack_type="SQL Injection", rule="sqli-union-pattern",
                   log_count=412, confidence=0.93, risk="high", status="blocked",
                   mitre_techniques=["T1190 Exploit Public-Facing Application"],
                   llm_summary={"what_happened": "UNION-based SQL injection against DVWA.",
                                "what_could_go_wrong": "User table could be exfiltrated.",
                                "what_should_be_done": "Block the IP and patch the endpoint."},
                   raw_log_sample=["GET /vulnerabilities/sqli/?id=1' UNION SELECT ..."])
        # ---- an uncertain event awaiting approval ----
        e2 = Event(source_ip="192.168.56.103", dest_ip="192.168.56.10",
                   attack_type="SSH Brute Force", rule="ssh-auth-fail",
                   log_count=38, confidence=0.61, risk="uncertain", status="awaiting",
                   mitre_techniques=["T1110 Brute Force"],
                   llm_summary={"what_happened": "38 failed SSH logins then one success.",
                                "what_could_go_wrong": "Possible credential compromise.",
                                "what_should_be_done": "Confirm with the account owner."})
        # ---- a low-risk logged event ----
        e3 = Event(source_ip="192.168.56.101", dest_ip="192.168.56.10",
                   attack_type="Port Scanning", rule="port-scan-syn",
                   log_count=96, confidence=0.18, risk="low", status="logged")
        db.session.add_all([e1, e2, e3])

        # ---- an attack chain ----
        chain = AttackChain(source_ip="192.168.56.102", highest_risk="high",
                            stage_count=4,
                            first_seen=datetime(2026, 3, 3), last_seen=datetime(2026, 7, 12),
                            stages=[
                                {"attack_type": "Port Scanning", "mitre": "T1046", "tactic": "Reconnaissance", "timestamp": "2026-03-03T09:14"},
                                {"attack_type": "SSH Brute Force", "mitre": "T1110", "tactic": "Credential Access", "timestamp": "2026-04-19T02:47"},
                                {"attack_type": "SQL Injection", "mitre": "T1190", "tactic": "Initial Access", "timestamp": "2026-06-28T23:08"},
                                {"attack_type": "Command Injection", "mitre": "T1059", "tactic": "Execution", "timestamp": "2026-07-12T14:02"},
                            ],
                            predicted_next="Web Shell")
        db.session.add(chain)

        # ---- a firewall block + a report ----
        db.session.add(BlockedIP(ip="192.168.56.102", attack_type="SQL Injection",
                                 blocked_by="auto", active=True))
        db.session.add(Report(title="Incident Report #42", risk="high",
                              resolution="auto_blocked", file_path="data/reports/demo.pdf"))

        # ---- asset inventory (this is what SMEs usually lack) ----
        from app.enrichment.asset_assessment import Asset
        db.session.add_all([
            Asset(ip="192.168.56.10", name="Target Server (DVWA)", criticality="critical",
                  owner="IT Team", os="Ubuntu 22.04",
                  services=["Apache", "MySQL", "SSH", "DVWA"]),
            Asset(ip="192.168.56.20", name="Spare Test Box", criticality="low",
                  owner="IT Team", os="Ubuntu 22.04", services=["SSH"]),
        ])

        # ---- vulnerability scan results for the target ----
        from app.enrichment.vuln_assessment import Vulnerability
        db.session.add_all([
            Vulnerability(ip="192.168.56.10", cve="CVE-2021-44228", cvss=10.0,
                          service="Apache", port=80, category="rce",
                          summary="Log4Shell remote code execution."),
            Vulnerability(ip="192.168.56.10", cve="CVE-2022-1234", cvss=8.8,
                          service="DVWA", port=80, category="sqli",
                          summary="SQL injection in the DVWA sqli module."),
        ])

        # ---- a couple of internal IPs treated as known-bad in the local feed ----
        os.makedirs("data/threat_feed", exist_ok=True)
        with open("data/threat_feed/blocklist.txt", "w") as fh:
            fh.write("# internal IPs flagged as known bad for the demo\n")
            fh.write("192.168.56.102\n192.168.56.107\n")

        db.session.commit()
        print("Seeded. Login as analyst01 / Analyst@2026 or manager01 / Manager@2026")


if __name__ == "__main__":
    seed()
