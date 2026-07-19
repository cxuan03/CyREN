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
    owner = db.Column(db.String(128))
    os = db.Column(db.String(64))
    services = db.Column(db.JSON)   # ["Apache", "MySQL", "SSH"]

    def to_dict(self):
        return {
            "id": self.id, "ip": self.ip, "name": self.name,
            "criticality": self.criticality, "owner": self.owner,
            "os": self.os, "services": self.services or [],
        }


class AssetAssessment:
    def lookup(self, ip: str) -> dict:
        """
        Return the asset record for an IP, or an 'unknown' placeholder.
        Safe to call outside an app context (returns 'unknown').
        """
        unknown = {"ip": ip, "name": None, "criticality": "unknown",
                   "owner": None, "os": None, "services": [], "risk_adjustment": 0}
        try:
            asset = Asset.query.filter_by(ip=ip).first()
        except Exception:
            return unknown
        if asset is None:
            return unknown
        d = asset.to_dict()
        d["risk_adjustment"] = CRITICALITY.get(asset.criticality, 0)
        return d

    def criticality_bump(self, ip: str) -> int:
        try:
            asset = Asset.query.filter_by(ip=ip).first()
        except Exception:
            return 0
        return CRITICALITY.get(asset.criticality, 0) if asset else 0


asset_assessment = AssetAssessment()
