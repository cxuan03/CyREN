"""
Seed the asset inventory with the laboratory hosts, keyed by IP.

Every entry is either a machine that really exists in the CyREN lab or a
declared internal workstation (an IP-addressed inventory entry) -- none of it is
fabricated telemetry. Assets are matched to events by IP (see
app/enrichment/asset_assessment.py), so declaring them gives the Triage and
Investigation agents real target context, and gives the Asset Management page
real rows.

Notes
-----
- The internal workstation range (192.168.56.20-.35) is an inventory
  declaration only; those IPs generate no traffic, so they never appear in an
  event and have ZERO effect on any risk score or evaluation metric.
- The target (.101) is kept at 'medium' criticality (risk bump 0) so it does
  not shift the reported evaluation numbers. Raise it later in the UI if you
  want to demonstrate criticality-aware triage.

Idempotent: upserts by IP, so it is safe to re-run.

Usage:
    python scripts/seed_assets.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.models.db import db
from app.enrichment.asset_assessment import Asset

# Real lab infrastructure -- (ip, name, criticality, owner, os, services)
# (ip, name, criticality, department, owner/employee-no, os, services)
INFRA = [
    ("192.168.56.101", "DVWA-WEB", "medium",   "Web Services",        "EMP-1101", "Web server running DVWA, the attack target of the lab"),
    ("192.168.56.1",   "LAB-HOST", "critical", "IT Infrastructure",   "EMP-1001", "Host that runs CyREN and the SIEM (Elasticsearch and Kibana)"),
]

# No declared workstations any more: the inventory holds only hosts that
# really exist in the lab (the target, the CyREN host and the SIEM). Add real
# machines through the Asset Management page.
WORKSTATIONS = []


def _upsert(ip, name, crit, department, owner, description):
    a = Asset.query.filter_by(ip=ip).first()
    if a is None:
        a = Asset(ip=ip)
        db.session.add(a)
    a.name, a.criticality, a.department, a.owner, a.description = \
        name, crit, department, owner, description


def main():
    app = create_app()
    with app.app_context():
        rows = INFRA + WORKSTATIONS
        for row in rows:
            _upsert(*row)
        db.session.commit()
        print(f"Seeded/updated {len(rows)} assets ({Asset.query.count()} total in inventory).")


if __name__ == "__main__":
    main()
