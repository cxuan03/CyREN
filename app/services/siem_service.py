"""
SIEM service: reads alerts from Elasticsearch and aggregates them into events.

Aggregation rule (matches Chapter 3): raw logs sharing the same source IP and
the same detection rule become one event, with log_count recording how many
raw entries were folded in.

The query targets the Kibana security alert index (default
`.alerts-security.alerts-default`), filtering on documents that carry
`kibana.alert.rule.name` -- the same query the validated prototype used.
"""
import ipaddress
import logging
import re
from collections import Counter, defaultdict

from config.settings import settings

try:
    from elasticsearch import Elasticsearch
except ImportError:
    Elasticsearch = None

log = logging.getLogger(__name__)

# fallback source-IP extraction from the log message, for alert documents that
# do not carry a parsed source.ip field (e.g. custom Filebeat log rules)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# "Failed password for invalid user x from 192.168.56.104 port 22" -> the
# attacker is the address after "from", not any other address on the line
_FROM_IP_RE = re.compile(r"\bfrom (\d{1,3}(?:\.\d{1,3}){3})\b")

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _parse_blacklist(raw: str):
    """Parse SOURCE_IP_BLACKLIST into (exact_ips, networks)."""
    exact, nets = set(), []
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        if "/" in item:
            try:
                nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                log.warning("[siem] ignoring invalid blacklist CIDR: %r", item)
        else:
            exact.add(item)
    return exact, nets


_BL_EXACT, _BL_NETS = _parse_blacklist(getattr(settings, "SOURCE_IP_BLACKLIST", ""))


def _is_blacklisted(ip: str) -> bool:
    """True if this source IP is noise (loopback, host gateway, ...)."""
    if not ip or ip == "unknown":
        return False
    if ip in _BL_EXACT:
        return True
    if _BL_NETS:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in _BL_NETS)
        except ValueError:
            return False
    return False


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


def _ip_from_message(message: str, host_ips: set) -> str:
    """Pull the attacker address out of a raw log line."""
    if not message:
        return ""
    # sshd lines name the attacker after "from"; prefer that over any other
    # address on the line (the target's own IP can appear too)
    match = _FROM_IP_RE.search(message)
    if match and match.group(1) not in host_ips:
        return match.group(1)
    for candidate in _IP_RE.findall(message):
        if candidate not in host_ips:
            return candidate
    return ""


def _extract_source_ip(source: dict, message: str) -> str:
    ip = _get(source, "source.ip") or _get(source, "kibana.alert.original_event.source.ip")
    if ip:
        return ip
    host_ip = _get(source, "host.ip")
    host_ips = set(host_ip if isinstance(host_ip, list) else [host_ip] if host_ip else [])
    return _ip_from_message(message, host_ips) or "unknown"


class SiemService:
    def __init__(self):
        self.es = None
        self._source_cache = {}
        if Elasticsearch is None:
            log.warning("[siem] elasticsearch package unavailable; running without a SIEM.")
            return
        try:
            self.es = Elasticsearch(
                settings.ELASTICSEARCH_URL,
                basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD),
            )
        except Exception as exc:
            log.error("[siem] could not connect to %s: %s", settings.ELASTICSEARCH_URL, exc)
            self.es = None

    def _source_docs_for_rule(self, alert_source: dict, since: str, until: str) -> list:
        """Fetch the raw log documents a rule fired on.

        Threshold rules aggregate on a field (here host.name) and the alert
        they emit carries only that aggregation key -- no message, no
        source.ip. To recover the attacker address we re-run the rule's own
        query against its own index over the alert's time window and read the
        originating log lines.
        """
        params = _get(alert_source, "kibana.alert.rule.parameters") or {}
        query = params.get("query")
        index = params.get("index") or _get(alert_source, "kibana.alert.rule.indices")
        if not query or not index:
            return []
        if isinstance(index, str):
            index = [index]

        cache_key = (",".join(index), query, since, until)
        if cache_key in self._source_cache:
            return self._source_cache[cache_key]

        try:
            resp = self.es.search(
                index=",".join(index),
                size=200,
                sort=[{"@timestamp": {"order": "asc"}}],
                query={"bool": {"filter": [
                    {"query_string": {"query": query}},
                    {"range": {"@timestamp": {"gte": since, "lte": until}}},
                ]}},
            )
            docs = [h["_source"] for h in resp["hits"]["hits"]]
        except Exception as exc:
            log.warning("[siem] could not read source logs for rule query %r: %s", query, exc)
            docs = []

        self._source_cache[cache_key] = docs
        return docs

    def _enrich_from_source_logs(self, alert_source: dict) -> tuple:
        """Return (source_ip, sample_messages) recovered from the raw logs."""
        threshold = _get(alert_source, "kibana.alert.threshold_result") or {}
        since = threshold.get("from") or _get(alert_source, "kibana.alert.original_time")
        until = _get(alert_source, "@timestamp")
        if not since or not until:
            return "", []

        # Widen the window with Elasticsearch date math: a threshold rule's
        # window can be just a few seconds, and the originating log lines may
        # sit slightly outside it, which used to leave the source IP "unknown".
        docs = self._source_docs_for_rule(alert_source, since + "||-10m", until + "||+2m")
        if not docs:
            return "", []

        host_ip = _get(alert_source, "host.ip")
        host_ips = set(host_ip if isinstance(host_ip, list) else [host_ip] if host_ip else [])

        messages, ips = [], Counter()
        for doc in docs:
            msg = (_get(doc, "message") or "")[:500]
            if msg:
                messages.append(msg)
            ip = _get(doc, "source.ip") or _ip_from_message(msg, host_ips)
            if ip:
                ips[ip] += 1
        # the address responsible for most of the lines in the window
        return (ips.most_common(1)[0][0] if ips else ""), messages[:50]

    def _query_alerts(self, size: int = 5000, hours: int = None) -> list:
        """
        Query the Kibana security alert index and normalise each hit into
        {id, source_ip, dest_ip, rule, severity, risk_score, message, timestamp}.
        """
        if self.es is None:
            return []   # skeleton mode
        hours = hours or settings.FETCH_WINDOW_HOURS
        self._source_cache = {}
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
            log.error("[siem] Elasticsearch query failed: %s", exc)
            return []

        alerts = []
        enriched = 0
        dropped = Counter()
        for hit in resp["hits"]["hits"]:
            source = hit["_source"]
            message = (_get(source, "message") or "")[:500]
            source_ip = _extract_source_ip(source, message)
            extra_logs = []

            # threshold alerts arrive without the original document: go back to
            # the raw logs for the attacker address and a real log sample
            if source_ip == "unknown":
                recovered_ip, sample = self._enrich_from_source_logs(source)
                if recovered_ip:
                    source_ip = recovered_ip
                    enriched += 1
                if sample:
                    extra_logs = sample
                    if not message:
                        message = sample[0][:500]

            # drop noise from loopback / the host-only gateway before it ever
            # becomes an event (configurable via SOURCE_IP_BLACKLIST)
            if _is_blacklisted(source_ip):
                dropped[source_ip] += 1
                continue

            alerts.append({
                "id": hit["_id"],
                "timestamp": _get(source, "@timestamp", ""),
                "rule": _get(source, "kibana.alert.rule.name", ""),
                "severity": _get(source, "kibana.alert.severity", "") or "",
                "risk_score": _get(source, "kibana.alert.risk_score", 0) or 0,
                "source_ip": source_ip,
                "dest_ip": _get(source, "destination.ip") or _get(source, "host.name", ""),
                "message": message,
                "source_logs": extra_logs,
            })

        by_rule = Counter(a["rule"] for a in alerts)
        log.info("[siem] fetched %d alert(s) from the last %dh across %d rule(s): %s",
                 len(alerts), hours, len(by_rule), dict(by_rule))
        if enriched:
            log.info("[siem] recovered the source IP from raw logs for %d alert(s)", enriched)
        if dropped:
            log.info("[siem] dropped %d blacklisted-source alert(s): %s",
                     sum(dropped.values()), dict(dropped))
        unresolved = sum(1 for a in alerts if a["source_ip"] == "unknown")
        if unresolved:
            log.warning("[siem] %d alert(s) still have no source IP; the rule emits no "
                        "message and its source logs could not be read", unresolved)
        return alerts

    def fetch_aggregated_events(self, hours: int = None) -> list:
        """Group raw alerts by (source_ip, rule) into events ready for triage."""
        raw = self._query_alerts(hours=hours)
        buckets = defaultdict(list)
        for alert in raw:
            key = (alert.get("source_ip", "unknown"), alert.get("rule", "unknown"))
            buckets[key].append(alert)

        events = []
        for (source_ip, rule), alerts in buckets.items():
            severity = max((a.get("severity") or "" for a in alerts),
                           key=lambda s: _SEVERITY_RANK.get(s.lower(), 0))
            timestamps = sorted(a.get("timestamp", "") for a in alerts if a.get("timestamp"))

            # prefer the real log lines recovered from the source index; fall
            # back to the alert messages for rules that carry them
            samples, seen = [], set()
            for alert in alerts:
                for line in (alert.get("source_logs") or []) or [alert.get("message", "")]:
                    if line and line not in seen:
                        seen.add(line)
                        samples.append(line)
                if len(samples) >= 50:
                    break

            events.append({
                "source_ip": source_ip,
                "dest_ip": alerts[0].get("dest_ip"),
                "rule": rule,
                "log_count": len(alerts),
                "raw_logs": samples[:50],
                "severity": severity,
                "risk_score": max(a.get("risk_score", 0) or 0 for a in alerts),
                "first_seen": timestamps[0] if timestamps else "",
                "last_seen": timestamps[-1] if timestamps else "",
            })

        log.info("[siem] aggregated into %d event(s): %s", len(events),
                 [(e["source_ip"], e["rule"], e["log_count"]) for e in events])
        return events


siem_service = SiemService()
