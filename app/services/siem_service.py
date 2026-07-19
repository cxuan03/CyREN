"""
SIEM service: reads alerts from Elasticsearch and aggregates them into events.

Aggregation rule (matches Chapter 3): raw logs sharing the same source IP and
the same detection rule become one event, with log_count recording how many
raw entries were folded in.

The query targets the Kibana security alert index (default
`.alerts-security.alerts-default`), filtering on documents that carry
`kibana.alert.rule.name` -- the same query the validated prototype used.
"""
import re
from collections import defaultdict

from config.settings import settings

try:
    from elasticsearch import Elasticsearch
except ImportError:
    Elasticsearch = None

# fallback source-IP extraction from the log message, for alert documents that
# do not carry a parsed source.ip field (e.g. custom Filebeat log rules)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _get(source: dict, dotted: str, default=None):
    """Read a field that may be stored flat ('kibana.alert.rule.name') or
    nested ({'kibana': {'alert': {'rule': {'name': ...}}}})."""
    if dotted in source:
        return source[dotted]
    node = source
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _extract_source_ip(source: dict, message: str) -> str:
    ip = _get(source, "source.ip") or _get(source, "kibana.alert.original_event.source.ip")
    if ip:
        return ip
    # fall back to the first IP in the message that is not the target host
    host_ip = _get(source, "host.ip")
    host_ips = set(host_ip if isinstance(host_ip, list) else [host_ip] if host_ip else [])
    for candidate in _IP_RE.findall(message or ""):
        if candidate not in host_ips:
            return candidate
    return "unknown"


class SiemService:
    def __init__(self):
        self.es = None
        if Elasticsearch is not None:
            try:
                self.es = Elasticsearch(
                    settings.ELASTICSEARCH_URL,
                    basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD),
                )
            except Exception:
                self.es = None

    def _query_alerts(self, size: int = 1000, hours: int = None) -> list:
        """
        Query the Kibana security alert index and normalise each hit into
        {id, source_ip, dest_ip, rule, severity, risk_score, message, timestamp}.
        """
        if self.es is None:
            return []   # skeleton mode
        hours = hours or settings.FETCH_WINDOW_HOURS
        try:
            resp = self.es.search(
                index=settings.ELASTIC_ALERT_INDEX,
                size=size,
                sort=[{"@timestamp": {"order": "desc"}}],
                query={"bool": {"filter": [
                    {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
                    {"exists": {"field": "kibana.alert.rule.name"}},
                ]}},
            )
        except Exception as exc:
            print(f"[siem] Elasticsearch query failed: {exc}")
            return []

        alerts = []
        for hit in resp["hits"]["hits"]:
            source = hit["_source"]
            message = (_get(source, "message") or "")[:500]
            alerts.append({
                "id": hit["_id"],
                "timestamp": _get(source, "@timestamp", ""),
                "rule": _get(source, "kibana.alert.rule.name", ""),
                "severity": _get(source, "kibana.alert.severity", "") or "",
                "risk_score": _get(source, "kibana.alert.risk_score", 0) or 0,
                "source_ip": _extract_source_ip(source, message),
                "dest_ip": _get(source, "destination.ip") or _get(source, "host.name", ""),
                "message": message,
            })
        return alerts

    def fetch_aggregated_events(self) -> list:
        """Group raw alerts by (source_ip, rule) into events ready for triage."""
        raw = self._query_alerts()
        buckets = defaultdict(list)
        for alert in raw:
            key = (alert.get("source_ip", "unknown"), alert.get("rule", "unknown"))
            buckets[key].append(alert)

        events = []
        for (source_ip, rule), alerts in buckets.items():
            severity = max((a.get("severity") or "" for a in alerts),
                           key=lambda s: _SEVERITY_RANK.get(s.lower(), 0))
            timestamps = sorted(a.get("timestamp", "") for a in alerts if a.get("timestamp"))
            events.append({
                "source_ip": source_ip,
                "dest_ip": alerts[0].get("dest_ip"),
                "rule": rule,
                "log_count": len(alerts),
                "raw_logs": [a.get("message", "") for a in alerts[:50]],
                "severity": severity,
                "risk_score": max(a.get("risk_score", 0) or 0 for a in alerts),
                "first_seen": timestamps[0] if timestamps else "",
                "last_seen": timestamps[-1] if timestamps else "",
            })
        return events


siem_service = SiemService()
