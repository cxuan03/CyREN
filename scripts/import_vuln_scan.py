"""
Import vulnerability scan results into the Vulnerability table.

    python scripts/import_vuln_scan.py <scan.xml|scan.csv>

TODO (FYP2 implementation):
    Parse your real scanner output. Two common sources:

    1. OpenVAS / Greenbone: export the report as XML, parse <result> nodes for
       host, nvt/@oid, cvss_base, and the CVE refs.
    2. Nmap vulners:  nmap -sV --script vulners <target> -oX scan.xml
       then parse the <script output="..."> blocks.

This stub shows the shape by inserting one demo finding.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.models.db import db
from app.enrichment.vuln_assessment import Vulnerability


def import_scan(path=None):
    app = create_app()
    with app.app_context():
        # ---- TODO: parse `path` (OpenVAS XML or nmap vulners) ----
        # demo insert so the flow is visible:
        v = Vulnerability(ip="192.168.56.10", cve="CVE-2023-9999", cvss=7.5,
                          service="OpenSSH", port=22, category="auth",
                          summary="Demo finding imported by import_vuln_scan.py")
        db.session.add(v)
        db.session.commit()
        print("Imported 1 finding (demo). Replace with your scanner parser.")


if __name__ == "__main__":
    import_scan(sys.argv[1] if len(sys.argv) > 1 else None)
