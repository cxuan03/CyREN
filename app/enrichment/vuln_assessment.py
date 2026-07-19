"""
Vulnerability Assessment enrichment
==================================
Answers "does the target actually have a weakness this attack could exploit?".
A SQL injection attempt against a fully patched app is noise; the same attempt
against a host with a matching unpatched CVE is an emergency. Knowing the
difference lets CyREN prioritise correctly.

CyREN keeps the results of periodic vulnerability scans (OpenVAS/Greenbone, or
Nmap with the vulners script) in a table keyed by IP. For a given event, it
checks whether any known vulnerability on the target matches the attack type.

TODO (FYP2 implementation):
    1. Run OpenVAS/Greenbone (or `nmap --script vulners`) against the Target
       Server VM on a schedule.
    2. Import the results with scripts/import_vuln_scan.py into the Vulnerability
       table.
    3. Refine _matches_attack with a proper attack-type -> CVE-category mapping.
"""
from datetime import datetime
from app.models.db import db


# rough mapping from attack type to the vulnerability categories it targets.
# Refine this with real CWE/CAPEC mappings.
ATTACK_TO_CATEGORY = {
    "SQL Injection": ["sqli", "injection", "cwe-89"],
    "Cross-Site Scripting": ["xss", "cwe-79"],
    "Command Injection": ["rce", "command", "cwe-78"],
    "SSH Brute Force": ["weak-credentials", "auth"],
    "Port Scanning": [],   # recon, no direct exploit match
}


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), index=True)
    cve = db.Column(db.String(32))
    cvss = db.Column(db.Float)
    service = db.Column(db.String(64))     # e.g. "Apache 2.4.49"
    port = db.Column(db.Integer)
    category = db.Column(db.String(64))    # e.g. "sqli", "rce"
    summary = db.Column(db.String(256))
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "ip": self.ip, "cve": self.cve, "cvss": self.cvss,
            "service": self.service, "port": self.port, "category": self.category,
            "summary": self.summary,
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
        }


class VulnAssessment:
    def _matches_attack(self, attack_type: str, vuln: Vulnerability) -> bool:
        cats = ATTACK_TO_CATEGORY.get(attack_type, [])
        cat = (vuln.category or "").lower()
        return any(c in cat for c in cats) if cats else False

    def assess(self, ip: str, attack_type: str) -> dict:
        """
        Return the target's known vulnerabilities and whether any of them match
        the current attack.

            {
              "ip": ...,
              "vuln_count": int,
              "exploitable": bool,          # a matching CVE exists
              "matching_cves": [...],
              "highest_cvss": float,
              "all": [...]
            }
        """
        try:
            vulns = Vulnerability.query.filter_by(ip=ip).all()
        except Exception:
            vulns = []
        matching = [v for v in vulns if self._matches_attack(attack_type, v)]
        return {
            "ip": ip,
            "vuln_count": len(vulns),
            "exploitable": len(matching) > 0,
            "matching_cves": [v.cve for v in matching],
            "highest_cvss": max([v.cvss or 0 for v in vulns], default=0),
            "all": [v.to_dict() for v in vulns],
        }


vuln_assessment = VulnAssessment()
