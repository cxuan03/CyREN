"""
Measure MTTD (Mean Time To Detect) from the Kibana security alert index.

For every alert, the detection latency is:

    MTTD = kibana.alert.@timestamp  -  kibana.alert.original_time
           (when the rule created the alert)   (the source event's own time)

i.e. how long after the malicious activity happened the detection rule fired.
It is bounded by each rule's schedule `interval` (a rule cannot alert before its
next scheduled run). Results are aggregated per rule (rules can have different
intervals) and overall.

    venv/Scripts/python.exe scripts/measure_mttd.py
    ... --hours 24        # only alerts whose @timestamp is within the last N hours
    ... --size 10000      # sample size (most recent alerts, desc)

Requires the Kibana detection engine to be running (producing alerts). If it is
not (e.g. filebeat-direct ingest with the engine off), there are no alert docs
to measure and MTTD can only be stated as the theoretical bound (rule interval).
"""
import argparse
import os
import sys
import statistics as st
from collections import defaultdict
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import settings                       # noqa: E402

try:
    from elasticsearch import Elasticsearch
except ImportError:
    print("Install elasticsearch first."); sys.exit(1)


def _get(src, dotted, default=None):
    """Read a field stored flat ('kibana.alert.rule.name') or nested."""
    if dotted in src:
        return src[dotted]
    node = src
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _parse(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default=os.getenv("ALERT_INDEX", ".alerts-security.alerts-default"))
    ap.add_argument("--size", type=int, default=10000)
    ap.add_argument("--hours", type=int, default=None, help="only alerts within the last N hours")
    args = ap.parse_args()

    es = Elasticsearch(settings.ELASTICSEARCH_URL,
                       basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))

    filters = [{"exists": {"field": "kibana.alert.rule.name"}}]
    if args.hours:
        filters.append({"range": {"@timestamp": {"gte": f"now-{args.hours}h"}}})

    resp = es.search(index=args.index, size=args.size,
                     sort=[{"@timestamp": {"order": "desc"}}],
                     query={"bool": {"filter": filters}})
    hits = resp["hits"]["hits"]

    per_rule = defaultdict(list)
    intervals = {}
    skipped_neg = 0
    for h in hits:
        s = h["_source"]
        rule = _get(s, "kibana.alert.rule.name")
        at = _parse(_get(s, "@timestamp"))
        ot = _parse(_get(s, "kibana.alert.original_time"))
        if not (rule and at and ot):
            continue
        mttd = (at - ot).total_seconds()
        if mttd < 0:                       # clock skew / threshold artefact
            skipped_neg += 1
            continue
        per_rule[rule].append(mttd)
        intervals.setdefault(rule, _get(s, "kibana.alert.rule.interval"))

    if not per_rule:
        print(f"No usable alerts in {args.index} "
              f"(engine off? try Kibana > Security > Alerts). "
              f"MTTD not measurable; state the rule interval as the theoretical bound.")
        return 1

    print(f"index={args.index}  sampled={len(hits)} alerts"
          + (f"  window=last {args.hours}h" if args.hours else "")
          + (f"  (skipped {skipped_neg} negative)" if skipped_neg else ""))
    print(f"\n{'Rule':30} {'n':>5} {'mean':>8} {'median':>8} {'p95':>8} {'interval':>9}")
    print("-" * 74)
    allv = []
    for rule, vals in sorted(per_rule.items()):
        allv.extend(vals)
        p95 = sorted(vals)[max(0, int(0.95 * len(vals)) - 1)]
        print(f"{rule:30} {len(vals):5d} {st.mean(vals):7.1f}s {st.median(vals):7.1f}s "
              f"{p95:7.1f}s {str(intervals.get(rule)):>9}")
    print("-" * 74)
    print(f"{'OVERALL':30} {len(allv):5d} {st.mean(allv):7.1f}s {st.median(allv):7.1f}s")
    print("\nMTTD = alert @timestamp - original_time; bounded by each rule's schedule interval.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
