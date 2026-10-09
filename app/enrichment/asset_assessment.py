"""
Asset Assessment enrichment
==========================
Answers "how important is the thing that was attacked?". An attack on a
critical database server is more serious than the same attack on a spare test
box, and the interface should reflect that.

This is the capability SMEs most often lack, because they have no asset
inventory at all. CyREN keeps a simple one: each known IP maps to an asset name,
a criticality tier, and an owner. The Triage agent uses the criticality to
adjust risk, and the Investigation agent passes it to the LLM as context.

Design: kept deliberately simple (a lookup table, not a CMDB integration),
because the SME value is in having *any* asset context, not in a heavyweight
system. This is a point worth making in the report.

TODO (FYP2 implementation):
    1. Populate the Asset table via scripts/seed_assets.py or the UI.
    2. Optionally sync from an external CMDB if the organisation has one.
"""
from app.models.db import db


# criticality tiers and the risk bump each applies
CRITICALITY = {
    "critical": 2,   # e.g. domain controller, primary database
    "high": 1,       # customer-facing app server
    "medium": 0,
    "low": -1,       # test / spare box
    "unknown": 0,
}


class Asset(db.Model):
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, index=True)
    name = db.Column(db.String(128))
    criticality = db.Column(db.String(16), default="unknown")   # critical|high|medium|low
    department = db.Column(db.String(128))   # owning department, e.g. "Finance"
    owner = db.Column(db.String(128))        # employee number / person, e.g. "EMP-1020"
    os = db.Column(db.String(64))            # legacy, no longer shown or edited
    services = db.Column(db.JSON)            # legacy, no longer shown or edited
    # what the machine is for and whose it is, in the administrator's own words,
    # e.g. "Web server running DVWA, the attack target of the lab"
    description = db.Column(db.String(300))

    def to_dict(self):
        return {
            "id": self.id, "ip": self.ip, "name": self.name,
            "criticality": self.criticality, "department": self.department,
            "owner": self.owner, "description": self.description,
        }


# The SIEM logs the lab target by hostname (host.name), not IP — so events carry
# dest_ip="target-server". Map those known hostnames to their real inventory IP so
# asset enrichment resolves. Real dest IPs (future attacks on other victims) match
# directly and skip this table.
SIEM_HOST_ALIASES = {
    "target-server": "192.168.56.101",   # DVWA-WEB
}


def resolve_dest_ip(dest) -> str:
    """Turn an event's dest (IP or SIEM hostname) into an inventory IP."""
    if not dest:
        return dest
    d = str(dest)
    if d in SIEM_HOST_ALIASES:
        return SIEM_HOST_ALIASES[d]
    return d


class AssetAssessment:
    def lookup(self, ip: str) -> dict:
        """
        Return the asset record for an IP (or SIEM hostname), or an 'unknown'
        placeholder. Safe to call outside an app context (returns 'unknown').
        """
        ip = resolve_dest_ip(ip)
        unknown = {"ip": ip, "name": None, "criticality": "unknown",
                   "owner": None, "os": None, "services": [], "risk_adjustment": 0}
        try:
            asset = Asset.query.filter_by(ip=ip).first()
            if asset is None:
                # also try matching by hostname/name for anything not aliased above
                pass
        except Exception:
            return unknown
        if asset is None:
            return unknown
        d = asset.to_dict()
        d["risk_adjustment"] = CRITICALITY.get(asset.criticality, 0)
        return d

    def criticality_bump(self, ip: str) -> int:
        ip = resolve_dest_ip(ip)
        try:
            asset = Asset.query.filter_by(ip=ip).first()
        except Exception:
            return 0
        return CRITICALITY.get(asset.criticality, 0) if asset else 0


asset_assessment = AssetAssessment()
