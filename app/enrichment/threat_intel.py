"""
Threat Intelligence enrichment
==============================
Looks up the reputation of a source IP and returns a structured verdict that
the Investigation agent feeds to the LLM, and that the Triage agent can use to
adjust risk.

Dual-mode lookup (this is the important design point):

    * PUBLIC IP  -> query external providers (AbuseIPDB / VirusTotal / OTX)
    * PRIVATE IP -> skip external providers (they have no data on RFC1918
                    addresses and it wastes API quota); query the LOCAL
                    threat feed instead (your own blocklist + previously
                    flagged IPs + an optional MISP instance).

This matters for an SME lab where almost all traffic is between internal
assets (192.168.x / 10.x / 172.16-31.x). Deciding where to look before
looking is both correct and quota-efficient.

TODO (FYP2 implementation):
    1. Put ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEY / OTX_API_KEY in .env.
    2. Fill in the real HTTP calls in _query_abuseipdb / _query_virustotal.
    3. Maintain data/threat_feed/blocklist.txt (one IP per line) or point
       MISP_URL at your MISP instance.
"""
import ipaddress
import os

from config.settings import settings

try:
    import requests
except ImportError:
    requests = None

# a small local feed so the skeleton produces useful results immediately.
# In the lab, add the internal IPs you want to treat as "known bad" here.
LOCAL_BLOCKLIST_PATH = os.path.join("data", "threat_feed", "blocklist.txt")
_DEMO_BLOCKLIST = {
    "192.168.56.102",   # the SQLi attacker in the demo data
    "192.168.56.107",
}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True   # unparseable -> treat as internal / unknown, don't leak to APIs


def _load_local_blocklist() -> set:
    ips = set(_DEMO_BLOCKLIST)
    if os.path.exists(LOCAL_BLOCKLIST_PATH):
        with open(LOCAL_BLOCKLIST_PATH) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    ips.add(line)
    return ips


class ThreatIntel:
    def __init__(self):
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.otx_key = os.getenv("OTX_API_KEY", "")

    # ---- external providers (public IPs only) ------------------------
    def _query_abuseipdb(self, ip: str) -> dict:
        """
        TODO: real AbuseIPDB call.
        GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>
        Header: Key: <ABUSEIPDB_API_KEY>
        Returns abuseConfidenceScore 0-100.
        """
        if requests is None or not self.abuseipdb_key:
            return {}
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                timeout=6,
            )
            data = r.json().get("data", {})
            return {"abuse_score": data.get("abuseConfidenceScore"),
                    "country": data.get("countryCode"),
                    "total_reports": data.get("totalReports")}
        except Exception:
            return {}

    def _query_virustotal(self, ip: str) -> dict:
        """
        TODO: real VirusTotal call.
        GET https://www.virustotal.com/api/v3/ip_addresses/<ip>
        Header: x-apikey: <VIRUSTOTAL_API_KEY>
        """
        if requests is None or not self.virustotal_key:
            return {}
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.virustotal_key}, timeout=6,
            )
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"vt_malicious": stats.get("malicious"),
                    "vt_suspicious": stats.get("suspicious")}
        except Exception:
            return {}

    # ---- local feed (private IPs, or as a first check) ---------------
    def _query_local(self, ip: str) -> dict:
        blocklist = _load_local_blocklist()
        return {"local_known_bad": ip in blocklist}

    # ------------------------------------------------------------------
    def lookup(self, ip: str) -> dict:
        """
        Returns a normalised verdict:
            {
              "ip": ...,
              "scope": "public" | "private",
              "known_bad": bool,
              "score": 0-100 (best available),
              "sources": [...],
              "detail": {...raw provider fields...}
            }
        """
        private = _is_private(ip)
        detail = {}
        sources = []
        score = 0
        known_bad = False

        # local feed is always consulted
        local = self._query_local(ip)
        detail.update(local)
        sources.append("local_feed")
        if local.get("local_known_bad"):
            known_bad = True
            score = max(score, 100)

        if not private:
            ab = self._query_abuseipdb(ip)
            if ab:
                detail.update(ab); sources.append("abuseipdb")
                score = max(score, ab.get("abuse_score") or 0)
            vt = self._query_virustotal(ip)
            if vt:
                detail.update(vt); sources.append("virustotal")
                if (vt.get("vt_malicious") or 0) > 0:
                    known_bad = True

        if score >= 75:
            known_bad = True

        return {
            "ip": ip,
            "scope": "private" if private else "public",
            "known_bad": known_bad,
            "score": score,
            "sources": sources,
            "detail": detail,
        }


threat_intel = ThreatIntel()
