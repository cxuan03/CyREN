"""
Export a labelled training set (CSV) from the events in the database, for the
XGBoost triage classifier (scripts/train_triage.py).

Labelling is by SOURCE IP:
    attack IPs  (.104/.150/.151) -> label 1  (true positive)
    benign IP   (.160)           -> label 0  (benign / false positive)
    any other source             -> skipped (not labelled)

Contaminated benign samples are dropped: the benign host's SSH Brute Force and
Port Scan events are NOT benign (its SSH used wrong credentials -> "Failed
password"; fast browsing tripped the port-scan rule), so only its SQL / XSS /
File Inclusion / Command Injection events are kept as clean negatives.

    venv/Scripts/python.exe scripts/export_training_set.py
    ... --attack-ips 192.168.56.104,192.168.56.150,192.168.56.151
    ... --benign-ips 192.168.56.160
    ... --out data/training_set.csv

IMPORTANT: source_ip is used ONLY to derive the label; it is NEVER written to
the training CSV as a feature (that would let the model memorise IPs instead
of learning behaviour). A separate manifest CSV records the IP -> label mapping
for auditing, kept apart from the training data.
"""
import argparse
import csv
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app                              # noqa: E402
from app.models.db import Event                         # noqa: E402
from app.agents.triage import has_attack_keyword        # noqa: E402  (shared logic)

# Keep in sync with scripts/train_triage.py RULE_MAP (the inference encoding).
RULE_MAP = {
    "SQL Injection Detected": 1,
    "XSS Attack Detected": 2,
    "Command Injection Detected": 3,
    "File Inclusion Detected": 4,
    "Port Scan Detected": 5,
    "SSH Brute Force Detected": 6,
}
# risk_score + severity_num per rule (Event does not persist these; derive them
# consistently with the values used in train_triage's patterns).
RULE_META = {
    "SQL Injection Detected":     {"risk_score": 73, "severity_num": 3},
    "XSS Attack Detected":        {"risk_score": 50, "severity_num": 2},
    "Command Injection Detected": {"risk_score": 73, "severity_num": 3},
    "File Inclusion Detected":    {"risk_score": 73, "severity_num": 3},
    "Port Scan Detected":         {"risk_score": 50, "severity_num": 2},
    "SSH Brute Force Detected":   {"risk_score": 90, "severity_num": 4},
}
# benign traffic on these rules is not actually benign -> drop from the set
BENIGN_EXCLUDE_RULES = {"SSH Brute Force Detected", "Port Scan Detected"}

# model feature columns (must match train_triage FEATURES) + optional behaviour
FEATURE_COLS = ["rule_encoded", "risk_score", "severity_num", "has_keyword", "request_count"]
BEHAVIOUR_COLS = ["duration_seconds", "request_rate_per_min"]


def _behaviour(e):
    dur = 0.0
    if e.first_seen and e.last_seen:
        dur = max(0.0, (e.last_seen - e.first_seen).total_seconds())
    minutes = dur / 60.0
    rate = float(e.log_count or 0) if minutes < 0.1 else round((e.log_count or 0) / minutes, 2)
    return round(dur, 1), rate


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack-ips", default="192.168.56.104,192.168.56.150,192.168.56.151")
    ap.add_argument("--benign-ips", default="192.168.56.160")
    ap.add_argument("--out", default="data/training_set.csv")
    ap.add_argument("--manifest", default="data/training_set_manifest.csv")
    args = ap.parse_args()

    attack_ips = {ip.strip() for ip in args.attack_ips.split(",") if ip.strip()}
    benign_ips = {ip.strip() for ip in args.benign_ips.split(",") if ip.strip()}

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_path = args.out if os.path.isabs(args.out) else os.path.join(root, args.out)
    man_path = args.manifest if os.path.isabs(args.manifest) else os.path.join(root, args.manifest)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    app = create_app()
    with app.app_context():
        events = Event.query.order_by(Event.id).all()

        rows, manifest = [], []
        counts = Counter()
        for e in events:
            ip, rule = e.source_ip, e.rule or ""
            if ip in attack_ips:
                label = 1
            elif ip in benign_ips:
                if rule in BENIGN_EXCLUDE_RULES:
                    counts["excluded_benign_contaminated"] += 1
                    continue
                label = 0
            else:
                counts["skipped_unlabelled"] += 1
                continue

            meta = RULE_META.get(rule, {"risk_score": 0, "severity_num": 1})
            dur, rate = _behaviour(e)
            row = {
                "rule_encoded": RULE_MAP.get(rule, 0),
                "risk_score": meta["risk_score"],
                "severity_num": meta["severity_num"],
                "has_keyword": has_attack_keyword(e.raw_log_sample),
                "request_count": e.log_count or 0,
                "duration_seconds": dur,
                "request_rate_per_min": rate,
                "label": label,
            }
            rows.append(row)
            manifest.append({"event_id": e.id, "source_ip": ip, "rule": rule,
                             "has_keyword": row["has_keyword"],
                             "request_count": row["request_count"], "label": label})
            counts["attack" if label == 1 else "benign"] += 1

        # training CSV: features + label, NO source_ip
        with open(out_path, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=FEATURE_COLS + BEHAVIOUR_COLS + ["label"])
            w.writeheader()
            w.writerows(rows)

        # manifest: audit trail (source_ip lives here only, never in training CSV)
        with open(man_path, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["event_id", "source_ip", "rule",
                                               "has_keyword", "request_count", "label"])
            w.writeheader()
            w.writerows(manifest)

    print(f"training set : {out_path}  ({len(rows)} rows)")
    print(f"manifest     : {man_path}")
    print(f"  attack (1) : {counts['attack']}")
    print(f"  benign (0) : {counts['benign']}")
    print(f"  excluded   : {counts['excluded_benign_contaminated']} "
          f"(benign SSH/Port Scan), {counts['skipped_unlabelled']} unlabelled sources")
    if counts["benign"] == 0:
        print("  WARNING: no benign samples. Run lab/benign_traffic.sh from .160 first.")
    print("\nTrain with:  venv/Scripts/python.exe scripts/train_triage.py --data " + args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
