"""
SIEM service: reads security telemetry from Elasticsearch and aggregates it
into events. Raw logs sharing the same source IP and the same detection rule
become one event, with log_count recording how many entries were folded in.

Two ingest modes (settings.INGEST_MODE):

  * "filebeat" (default): read the detection-rule *definitions* from Kibana,
    then run those queries directly against the raw filebeat logs and build
    events from the matches. This does NOT depend on the Kibana detection
    engine running, so both attack and benign traffic become events reliably.

  * "alerts": read the Kibana security alert index
    (`.alerts-security.alerts-default`, docs carrying `kibana.alert.rule.name`).
    Only works while the Kibana detection rules are enabled and firing.

Both paths share the same IP extraction, blacklist filtering and aggregation.
"""
import ipaddress
import logging
import re
import time
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

# Used only if the detection-rule definitions cannot be read from Kibana.
# Values mirror the Kibana rules as of 2026-10-10. The queries are path-based
# (so real payloads and benign visits both match); query_string needs
# uppercase AND.
_FALLBACK_RULES = [
    {"name": "SQL Injection Detected",
     "query": 'host.name: "target-server" AND message: "vulnerabilities/sqli"',
     "index": ["filebeat-*"], "severity": "high", "risk_score": 73},
    {"name": "XSS Attack Detected",
     "query": 'host.name: "target-server" AND message: "vulnerabilities/xss_r"',
     "index": ["filebeat-*"], "severity": "medium", "risk_score": 50},
    {"name": "Command Injection Detected",
     "query": 'host.name: "target-server" AND message: "vulnerabilities/exec"',
     "index": ["filebeat*"], "severity": "high", "risk_score": 73},
    {"name": "File Inclusion Detected",
     "query": 'host.name: "target-server" AND message: "vulnerabilities/fi"',
     "index": ["filebeat*"], "severity": "high", "risk_score": 73},
    {"name": "SSH Brute Force Detected",
     "query": 'host.name: "target-server" AND message: "Failed password"',
     "index": ["filebeat*"], "severity": "critical", "risk_score": 90},
    {"name": "Port Scan Detected",
     "query": 'host.name: "target-server" AND message: "PORTSCAN"',
     "index": ["filebeat*"], "severity": "medium", "risk_score": 50},
]


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


def _kql_to_lucene(query: str) -> str:
    """Kibana stores rule queries in KQL, which uses lowercase and/or/not.
    Elasticsearch query_string is Lucene, where those must be uppercase or they
    are treated as literal search terms (matching almost everything). Uppercase
    the operators only OUTSIDE double-quoted values so phrases are untouched."""
    parts = query.split('"')
    for i in range(0, len(parts), 2):        # even segments are outside quotes
        parts[i] = re.sub(r"(?i)(?<![\w.])(and|or|not)(?![\w.])",
                          lambda m: m.group(1).upper(), parts[i])
    return '"'.join(parts)


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


class _EsBreaker:
    """Circuit breaker around the Elasticsearch client.

    When a call fails with a connection error, every further call for the
    next `hold` seconds fails at once (same exception type) instead of waiting
    for another TCP timeout. With Elasticsearch down, a page that makes two or
    three ES calls used to take ten seconds; now only the first call in each
    window pays the timeout and the rest return immediately. The callers'
    existing `except Exception` branches handle the raised error as before."""
    hold = 20.0

    def __init__(self, client):
        self._c = client
        self._down_until = 0.0

    def _wrap(self, fn):
        def call(*a, **kw):
            if time.time() < self._down_until:
                raise ConnectionError("Elasticsearch unreachable (recent failure, retry in a few seconds)")
            try:
                return fn(*a, **kw)
            except Exception as exc:
                name = type(exc).__name__
                if "Connection" in name or "Timeout" in name:
                    self._down_until = time.time() + self.hold
                raise
        return call

    def __getattr__(self, item):
        attr = getattr(self._c, item)
        return self._wrap(attr) if callable(attr) else attr


class SiemService:
    def __init__(self):
        self.es = None
        self._source_cache = {}
        self._rule_cache = (0.0, None)     # (fetched_at, defs) — see _rule_defs
        if Elasticsearch is None:
            log.warning("[siem] elasticsearch package unavailable; running without a SIEM.")
            return
        try:
            # Fast-fail defaults so a slow/unreachable Elasticsearch can NEVER hang
            # a web request (e.g. the dashboard's "logs collected" count): bound
            # every call to a few seconds and do not retry on a dead connection.
            # Long operations (delete_by_query) still override request_timeout.
            self.es = _EsBreaker(Elasticsearch(
                settings.ELASTICSEARCH_URL,
                basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD),
                request_timeout=3, max_retries=0, retry_on_timeout=False,
            ))
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
                    {"query_string": {"query": _kql_to_lucene(query)}},
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
                    {"range": {"@timestamp": {"gte": self._ingest_gte(hours), "lte": "now"}}},
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

    def _rule_defs(self) -> list:
        """Enabled detection-rule definitions (name, query, index, severity,
        risk_score), read from Kibana. Used by the filebeat-direct ingest so
        CyREN matches the same queries the analyst configured, without needing
        the Kibana detection engine to be running.

        Cached for 60 seconds: the Event Details page and the poller both call
        this, and rule definitions change rarely, so one Kibana read a minute
        is plenty. While Elasticsearch is down the fallback set is cached too,
        so a page never waits on a dead connection more than once a minute."""
        fetched_at, cached = self._rule_cache
        if cached is not None and time.time() - fetched_at < 60:
            return cached
        defs = self._read_rule_defs()
        self._rule_cache = (time.time(), defs)
        return defs

    def _read_rule_defs(self) -> list:
        try:
            # .kibana_alerting_cases* is a Kibana SYSTEM index: Elasticsearch warns
            # that direct reads of it may be blocked in a future major version.
            # Reading it is still the only way to get the rule definitions
            # without the Kibana API, so keep the read and quiet the warning.
            import warnings
            from elasticsearch import ElasticsearchWarning
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", ElasticsearchWarning)
                res = self.es.search(index=settings.KIBANA_RULES_INDEX, size=200,
                                      query={"term": {"type": "alert"}})
        except Exception as exc:
            log.warning("[siem] could not read Kibana rule defs (%s); using fallback set", exc)
            return _FALLBACK_RULES

        defs = []
        for hit in res["hits"]["hits"]:
            a = hit["_source"].get("alert", {})
            if not a.get("enabled"):
                continue
            p = a.get("params", {}) or {}
            query = p.get("query")
            if not query:
                continue
            idx = p.get("index") or [settings.FILEBEAT_INDEX]
            defs.append({
                "name": a.get("name"),
                "query": query,
                "index": idx if isinstance(idx, list) else [idx],
                "severity": p.get("severity", "") or "",
                # Kibana stores the rule risk score as camelCase "riskScore";
                # keep "risk_score" as a fallback for older exports.
                "risk_score": p.get("riskScore") or p.get("risk_score") or 0,
            })
        if not defs:
            log.warning("[siem] no enabled Kibana rules found; using fallback set")
            return _FALLBACK_RULES
        log.info("[siem] using %d detection rule(s) from Kibana for filebeat ingest", len(defs))
        return defs

    def _ingest_gte(self, hours):
        """Lower bound for ingest queries: the LATER of (now - lookback) and the
        'ingest_since' watermark. A lab reset sets that watermark to now, so the
        poller stops re-ingesting the OLD logs still sitting in Elasticsearch
        and only picks up genuinely new attack traffic."""
        from datetime import datetime, timedelta
        floor = datetime.utcnow() - timedelta(hours=hours)
        try:
            from app.models.db import Setting
            wm = Setting.get("ingest_since")
            if wm:
                wdt = datetime.fromisoformat(str(wm).replace("Z", "")[:19])
                if wdt > floor:
                    floor = wdt
        except Exception:
            pass
        return floor.strftime("%Y-%m-%dT%H:%M:%S")

    def _query_filebeat(self, hours: int = None) -> list:
        """Match each detection rule's query directly against the raw filebeat
        logs and normalise the hits into the same alert shape as _query_alerts.
        Independent of the Kibana detection engine."""
        if self.es is None:
            return []
        hours = hours or settings.FETCH_WINDOW_HOURS
        alerts, dropped, unresolved = [], Counter(), 0
        for rule in self._rule_defs():
            idx = rule.get("index") or [settings.FILEBEAT_INDEX]
            try:
                resp = self.es.search(
                    index=",".join(idx),
                    size=settings.FILEBEAT_MAX_DOCS,
                    sort=[{"@timestamp": {"order": "desc"}}],
                    query={"bool": {"filter": [
                        {"range": {"@timestamp": {"gte": self._ingest_gte(hours), "lte": "now"}}},
                        {"query_string": {"query": _kql_to_lucene(rule["query"])}},
                    ]}},
                )
            except Exception as exc:
                log.warning("[siem] filebeat query for rule %r failed: %s", rule["name"], exc)
                continue

            for hit in resp["hits"]["hits"]:
                s = hit["_source"]
                message = (_get(s, "message") or "")[:500]
                source_ip = _extract_source_ip(s, message)
                if source_ip == "unknown":
                    unresolved += 1
                    continue
                if _is_blacklisted(source_ip):
                    dropped[source_ip] += 1
                    continue
                alerts.append({
                    "id": hit["_id"],
                    "timestamp": _get(s, "@timestamp", ""),
                    "rule": rule["name"],
                    "severity": rule.get("severity", ""),
                    "risk_score": rule.get("risk_score", 0),
                    "source_ip": source_ip,
                    "dest_ip": _get(s, "destination.ip") or _get(s, "host.name", ""),
                    "message": message,
                    "source_logs": [message],
                })

        by_rule = Counter(a["rule"] for a in alerts)
        log.info("[siem] filebeat ingest: %d matching log(s) over %dh across %d rule(s): %s",
                 len(alerts), hours, len(by_rule), dict(by_rule))
        if dropped:
            log.info("[siem] dropped %d blacklisted-source log(s): %s",
                     sum(dropped.values()), dict(dropped))
        if unresolved:
            log.info("[siem] %d matching log(s) had no extractable source IP", unresolved)
        return alerts

    def fetch_aggregated_events(self, hours: int = None) -> list:
        """Group raw alerts by (source_ip, rule) into events ready for triage.

        The source of the raw alerts depends on INGEST_MODE:
        filebeat (default) matches rule queries against raw logs; alerts reads
        the Kibana alert index; both unions them.
        """
        mode = getattr(settings, "INGEST_MODE", "alerts")
        if mode == "filebeat":
            raw = self._query_filebeat(hours=hours)
        elif mode == "both":
            raw = self._query_alerts(hours=hours) + self._query_filebeat(hours=hours)
        else:
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

            # Collect the candidate log lines, then keep payload-bearing lines
            # first so the 50-line sample represents actual attack strings even
            # when benign traffic to the same path dominates the volume (this
            # is what lets has_keyword see a real payload).
            from app.agents.triage import has_attack_keyword
            seen, uniq = set(), []
            for alert in alerts:
                for line in (alert.get("source_logs") or []) or [alert.get("message", "")]:
                    if line and line not in seen:
                        seen.add(line)
                        uniq.append(line)
            uniq.sort(key=lambda ln: 0 if has_attack_keyword([ln]) else 1)
            samples = uniq[:50]

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

    def search_raw_logs(self, q=None, source_ip=None, start=None, end=None,
                        page=1, per=50, order="desc"):
        """Read raw filebeat log documents for the Raw Logs viewer — a live,
        read-only window into Elasticsearch (nothing is copied into CyREN's DB).

        Returns (rows, total). Each row: {id, timestamp, source_ip, dest, rule,
        message}. Optional free-text `q` (Lucene), `source_ip`, and a
        [start, end) time window (naive UTC datetimes). Paginated.
        """
        if self.es is None:
            return None, 0
        filters = []
        if start or end:
            rng = {}
            if start:
                rng["gte"] = start.isoformat()
            if end:
                rng["lt"] = end.isoformat()
            filters.append({"range": {"@timestamp": rng}})
        if source_ip:
            # match a parsed source.ip OR the address appearing in the message
            filters.append({"bool": {"should": [
                {"term": {"source.ip": source_ip}},
                {"match_phrase": {"message": source_ip}},
            ], "minimum_should_match": 1}})
        if q:
            filters.append({"query_string": {"query": _kql_to_lucene(q),
                                              "default_field": "message"}})
        query = {"bool": {"filter": filters}} if filters else {"match_all": {}}
        frm = max(0, (int(page) - 1) * int(per))
        if order not in ("asc", "desc"):
            order = "desc"
        try:
            resp = self.es.search(
                index=settings.FILEBEAT_INDEX, from_=frm, size=int(per),
                sort=[{"@timestamp": {"order": order}}],
                query=query, request_timeout=6, track_total_hits=True)
        except Exception as exc:
            log.warning("[siem] search_raw_logs failed: %s", exc)
            return None, 0
        rows = []
        for hit in resp["hits"]["hits"]:
            s = hit["_source"]
            msg = (_get(s, "message") or "")[:800]
            rows.append({
                "id": hit["_id"],
                "timestamp": _get(s, "@timestamp", ""),
                "source_ip": _extract_source_ip(s, msg),
                "dest": _get(s, "destination.ip") or _get(s, "host.name", ""),
                "rule": _get(s, "event.category") or _get(s, "log.file.path") or "",
                "message": msg,
                "raw": {k: s[k] for k in list(s)[:40]},
            })
        total = resp["hits"]["total"]
        total = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
        return rows, total

    def purge_filebeat_before(self, cutoff_iso):
        """DELETE filebeat log documents older than cutoff_iso (an ISO string).
        Destructive — used by a lab reset with --purge-es to actually clear the
        old telemetry from Elasticsearch. Returns how many docs were deleted."""
        if self.es is None:
            return 0
        resp = self.es.delete_by_query(
            index=settings.FILEBEAT_INDEX,
            query={"range": {"@timestamp": {"lt": cutoff_iso}}},
            conflicts="proceed", request_timeout=120, refresh=True)
        return int(resp.get("deleted", 0))

    def latest_log_time(self):
        """The newest @timestamp in the filebeat index (ISO string), or None.
        Used to warn the analyst when log shipping has stalled."""
        if self.es is None:
            return None
        try:
            resp = self.es.search(index=settings.FILEBEAT_INDEX, size=0,
                                  aggs={"m": {"max": {"field": "@timestamp"}}},
                                  request_timeout=6)
            return resp["aggregations"]["m"].get("value_as_string")
        except Exception as exc:
            log.warning("[siem] latest_log_time failed: %s", exc)
            return None

    def fetch_raw_logs_by_ids(self, ids):
        """Fetch specific raw log documents by their ES _id (the Report
        Builder's hand-picked rows). Same row shape as search_raw_logs,
        newest first. Returns None if Elasticsearch is unavailable."""
        if self.es is None or not ids:
            return None if self.es is None else []
        try:
            resp = self.es.search(
                index=settings.FILEBEAT_INDEX, size=len(ids),
                sort=[{"@timestamp": {"order": "desc"}}],
                query={"ids": {"values": list(ids)}}, request_timeout=6)
        except Exception as exc:
            log.warning("[siem] fetch_raw_logs_by_ids failed: %s", exc)
            return None
        rows = []
        for hit in resp["hits"]["hits"]:
            s = hit["_source"]
            msg = (_get(s, "message") or "")[:800]
            rows.append({
                "id": hit["_id"],
                "timestamp": _get(s, "@timestamp", ""),
                "source_ip": _extract_source_ip(s, msg),
                "dest": _get(s, "destination.ip") or _get(s, "host.name", ""),
                "rule": _get(s, "event.category") or _get(s, "log.file.path") or "",
                "message": msg,
            })
        return rows

    def count_logs(self, start=None, end=None):
        """Total raw log documents in the filebeat index, optionally within a
        [start, end) window (naive UTC datetimes, as the app stores them).

        This backs the dashboard's "logs collected" figure: the real volume of
        telemetry Filebeat shipped into Elasticsearch, not just the lines that
        matched a detection rule. Returns None if Elasticsearch is unavailable
        so the caller can fall back to the aggregated event log-line sum.
        """
        if self.es is None:
            return None
        import time
        now = time.time()
        # circuit-breaker: after a failure, stop hammering a down ES for 30s so
        # the dashboard does not wait on the timeout on every poll.
        if now < getattr(self, "_count_cooldown_until", 0.0):
            return None
        # short cache: the dashboard auto-refreshes every few seconds, but the raw
        # log volume barely changes second-to-second. Reuse a recent count for the
        # SAME window for 20s so each refresh doesn't pay a fresh ES round-trip.
        ck = (start.isoformat() if start else None, end.isoformat() if end else None)
        cached = getattr(self, "_count_cache", None)
        if cached and cached[0] == ck and now - cached[2] < 20:
            return cached[1]
        # "logs collected" reflects the REAL Elasticsearch volume for the
        # requested window and nothing else: the dashboard's date preset already
        # sends a local-day [from, to] range (e.g. "Today" = Kuala-Lumpur
        # midnight -> now), so this count matches exactly what Kibana shows for
        # the same range. No ingest-watermark clamp here — the watermark still
        # governs which logs become events (see _ingest_gte), but it must not
        # shrink this display figure below the window the user actually picked.
        try:
            query = {"match_all": {}}
            if start or end:
                rng = {}
                if start:
                    rng["gte"] = start.isoformat()
                if end:
                    rng["lt"] = end.isoformat()
                query = {"bool": {"filter": [{"range": {"@timestamp": rng}}]}}
            resp = self.es.count(index=settings.FILEBEAT_INDEX, query=query,
                                 request_timeout=2)
            val = int(resp.get("count", 0))
            self._count_cache = (ck, val, now)
            return val
        except Exception as exc:
            self._count_cooldown_until = now + 30
            log.warning("[siem] count_logs failed (%s); backing off 30s", exc)
            return None


siem_service = SiemService()
